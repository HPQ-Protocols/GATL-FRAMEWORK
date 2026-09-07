import gc
import hashlib
import hmac
import json
import os
import tracemalloc

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def checked(condition, message):
    if not condition:
        raise RuntimeError(message)

def immutable(path, value):
    data = canonical(value) + b"\n"
    if path.exists():
        checked(path.read_bytes() == data, "Immutable artifact changed: " + str(path))
    else:
        with path.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    return sha(data)

def tasks(trace, plan, design):
    result = []
    for replicate in range(design["replicates"]):
        count = max(design["latency_n"], design["loss_n"], design["budget_n"],
                    design["components_n"], design["raw_n"], design["memory_n"])
        records = trace.generate(plan, "benchmark", count, replicate=replicate)
        for record in records:
            if record["trial_id"] < design["loss_n"] or (
                    record["scenario_id"] == "iid_p20" and record["trial_id"] < design["latency_n"]):
                result.append({"family": "primary", "budget": None, "record": record})
        reference = [record for record in records if record["scenario_id"] == "iid_p20"]
        for record in reference:
            if record["trial_id"] < design["budget_n"]:
                budgets = list(plan["byte_budget"]["budgets"])
                shift = record["trial_id"] % len(budgets)
                for budget in budgets[shift:] + budgets[:shift]:
                    result.append({"family": "budget", "budget": budget, "record": record})
        for family, count in (("components", design["components_n"]), ("raw_ablation", design["raw_n"]),
                              ("memory", design["memory_n"])):
            for record in reference[:count]:
                if family == "memory":
                    record = dict(record, received_mask=31, scenario_id="memory_all_received_fixture")
                result.append({"family": family, "budget": None, "record": record})
    return result

def task_id(task):
    return sha(canonical(task))

def validate_rows(rows, task, trace, plan, design):
    record, family = task["record"], task["family"]
    checked(len(rows) == len(trace.METHODS), "Incomplete paired block.")
    checked([row["method"] for row in rows] == record["method_order"], "Method order changed.")
    for position, row in enumerate(rows):
        method = row["method"]
        for name in ("replicate", "trial_id", "scenario_id", "received_mask"):
            checked(row[name] == record[name], "Trace metadata mismatch: " + name)
        checked(row["trace_phase"] == record["phase"] and row["family"] == family
                and row["budget"] == task["budget"] and row["method_position"] == position,
                "Observation metadata mismatch.")
        send_mask = 1 if method == "native" else 31
        if family == "budget":
            send_mask = plan["byte_budget"]["allocations"][str(task["budget"])][method]["send_mask"]
        checked(row["send_mask"] == send_mask, "Send mask differs from frozen allocation.")
        expected = trace.policy_allows(method, record["received_mask"] & send_mask)
        checked(type(row["success"]) is bool and row["success"] == expected, "Observed success mismatch.")
        checked(row["decapsulation_calls"] == int(expected), "Unexpected Decaps count.")
        checked(row["error_type"] is None and row["error_code"] is None, "Error row cannot be committed.")
        if expected:
            checked(row["ciphertext_equal"] is True and row["key_equal"] is True, "Missing C/K equality.")
        else:
            checked(row["ciphertext_equal"] is None and row["key_equal"] is None, "Failure has candidate equality.")
        if family == "memory":
            checked(type(row["python_traced_peak_bytes"]) is int and row["python_traced_peak_bytes"] >= 0,
                    "Invalid traced memory measurement.")
        else:
            checked(row["transport_processing_ns"] == row["send_ns"] + row["receive_ns"], "Timer sum changed.")
            checked((row["successful_transport_until_release_ns"] is not None) == expected,
                    "Successful-time conditioning mismatch.")
            checked(row["receive_calls"] == len(trace.delivered_nodes(record, method, send_mask)),
                    "Not all received packets processed.")
            for name, value in row.items():
                if name.endswith("_ns") and value is not None:
                    checked(type(value) is int and value >= 0, "Invalid elapsed time: " + name)
            if family != "raw_ablation":
                sizes = plan["byte_budget"]["packet_sizes"][method]
                scheduled = sum(sizes[node] for index, node in enumerate(trace.NODES)
                                if send_mask & (1 << index))
                checked(row["application_bytes"] == scheduled == row["scheduled_bytes"], "Byte accounting mismatch.")
                checked(row["generated_bytes"] == sum(sizes.values()), "Full encoding cost not retained.")
            else:
                checked(row["mode"] == "raw" and row["application_bytes"] is None, "Raw ablation mislabeled.")
            checked(row["lower_layer_wire_bytes"] is None and row["control_bytes"] is None,
                    "Unsupported wire/control measurement.")

def append_block(handle, task, rows, previous):
    payload = {"task_id": task_id(task), "previous": previous, "rows": rows}
    digest = sha(canonical(payload))
    handle.write(canonical(dict(payload, sha256=digest)) + b"\n")
    handle.flush()
    os.fsync(handle.fileno())
    return digest

def scan(directory, expected_tasks, validate):
    completed, files, tails = set(), {}, []
    for segment in sorted(directory.glob("segment_*")):
        checked(not (segment / "fatal.json").exists(), "Fatal benchmark error: inspect " + str(segment))
        path = segment / "blocks.jsonl"
        if not path.exists():
            continue
        finish = segment / "finished.json"
        if finish.exists():
            seal = json.loads(finish.read_bytes())
            checked(seal["journal_sha256"] == file_sha(path), "Sealed journal changed.")
            for name, digest in seal["additional_files"].items():
                checked(file_sha(segment / name) == digest, "Sealed segment metadata changed.")
        previous, count = "0" * 64, 0
        with path.open("rb") as handle:
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    tails.append({"path": str(path.name), "segment": segment.name, "offset": offset,
                                  "bytes": len(line), "sha256": sha(line), "action": "preserve_not_count_incomplete_block"})
                    break
                envelope = json.loads(line)
                digest = envelope.pop("sha256")
                checked(digest == sha(canonical(envelope)) and envelope["previous"] == previous,
                        "Broken journal hash chain.")
                identity = envelope["task_id"]
                checked(identity in expected_tasks and identity not in completed, "Unknown or duplicated paired block.")
                validate(envelope["rows"], expected_tasks[identity])
                completed.add(identity)
                previous, count = digest, count + 1
        files[str(path.relative_to(directory))] = {"sha256": file_sha(path), "blocks": count,
                                                   "rows": count * 7, "last_hash": previous}
    return completed, files, tails

def memory_block(factory, auth, mlkem, kem, trace, entries, runner, task):
    checked(not tracemalloc.is_tracing(), "Stop external tracemalloc before Cell 10.")
    record = task["record"]
    ciphertext, sender_key = kem.encaps(runner.public_key)
    senders, receivers = factory(), factory()
    for position, method in enumerate(record["method_order"]):
        endpoint = None
        gc.collect()
        tracemalloc.start(1)
        try:
            channel = auth.AuthChannel(entries[method], senders[method], receivers[method],
                                       "sender-A", "receiver-B", mlkem.key_id(runner.public_key), clock=lambda: 0.0)
            endpoint = mlkem.VerifiedKEMReceiver(channel, kem, runner.public_key, runner.secret_key)
            context = channel.admit()
            packets = channel.send(context, ciphertext)
            released = []
            for node in trace.delivered_nodes(record, method):
                result = endpoint.receive(packets[node])
                if result.status == "KEY_CANDIDATE":
                    released.append(result)
            current, peak = tracemalloc.get_traced_memory()
            checked(len(released) == 1 and released[0].ciphertext == ciphertext
                    and hmac.compare_digest(released[0].candidate_key, sender_key), "Memory pass C/K check failed.")
            calls = endpoint.decapsulation_calls
        finally:
            tracemalloc.stop()
            if endpoint is not None:
                endpoint.close()
        yield {"trace_phase": record["phase"], "replicate": record["replicate"], "trial_id": record["trial_id"],
               "scenario_id": record["scenario_id"], "received_mask": record["received_mask"], "family": "memory",
               "budget": None, "method": method, "method_position": position, "send_mask": 1 if method == "native" else 31,
               "success": True, "ciphertext_equal": True, "key_equal": True, "decapsulation_calls": calls,
               "error_type": None, "error_code": None, "python_traced_peak_bytes": peak,
               "python_traced_current_bytes": current,
               "memory_scope": "Python_traced_session_setup_send_receive_including_harness_excluding_prior_codecs_keys_native_allocations",
               "is_latency_measurement": False, "is_RSS_measurement": False}
