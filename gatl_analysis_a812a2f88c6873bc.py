import hashlib
import json
import math
import statistics
import types
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

LABELS = {
    "native": "Native", "replication": "Replication", "rs_3_5": "RS (3,5)",
    "shamir_3_5": "Shamir (3,5)", "gatl_uniform_3_5": "GATL-uniform",
    "gatl_gateway": "GATL-gateway", "rs_2_5_gateway_check": "RS (2,5) + policy check",
}

def checked(condition, label):
    if not condition:
        raise RuntimeError(label)

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

def inside(root, relative):
    path = Path(relative)
    checked(not path.is_absolute() and ".." not in path.parts, "Unsafe artifact path.")
    return root / path

def verified(root, relative, digest):
    path = inside(root, relative)
    checked(file_sha(path) == digest, "Artifact hash mismatch: " + str(relative))
    return path

def load_module(path, name):
    module = types.ModuleType(name)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module

def audit(run_dir, config):
    benchmark_config = config["benchmark"]
    manifest_path = verified(run_dir, benchmark_config["manifest"], benchmark_config["manifest_sha256"])
    manifest = json.loads(manifest_path.read_bytes())
    checked(manifest["status"] == "PASS" and manifest["is_final_benchmark"] is True
            and manifest["uses_real_mlkem"] is True and manifest["pilot_included_as_final_data"] is False,
            "Not a completed real-KEM benchmark.")
    checked(manifest["run_id"] == run_dir.name and manifest["design_id"] == benchmark_config["design_id"],
            "Run/design mismatch.")
    directory = inside(run_dir, manifest["files_relative_to"])
    checked(directory == inside(run_dir, benchmark_config["directory"]), "Benchmark directory mismatch.")
    design = json.loads(verified(run_dir, manifest["design_file"], manifest["design_file_sha256"]).read_bytes())
    checked(sha(canonical(design)) == manifest["design_id"], "Design identity mismatch.")
    plan = json.loads(verified(run_dir, config["trace_design"]["plan"], manifest["base_plan_sha256"]).read_bytes())
    checked(config["trace_design"]["plan_sha256"] == manifest["base_plan_sha256"], "Base plan changed.")
    source = verified(run_dir, benchmark_config["source"], manifest["controller_source_sha256"])
    checked(benchmark_config["source_sha256"] == manifest["controller_source_sha256"]
            == design["controller_source_sha256"], "Controller provenance mismatch.")
    controller = load_module(source, "cell11_verified_controller")
    trace_source = verified(run_dir, config["trace_design"]["source"], config["trace_design"]["source_sha256"])
    checked(plan["trace_source_sha256"] == config["trace_design"]["source_sha256"], "Trace source changed.")
    trace = load_module(trace_source, "cell11_verified_trace")
    checked(plan["numpy_version"] == np.__version__, "NumPy changed; preserve the trace runtime for this cell.")
    for section in ("sharing", "baselines", "authentication", "kem", "runner"):
        expected = manifest["runner_source_sha256"] if section == "runner" else plan["input_hashes"][section]
        checked(config[section]["source_sha256"] == expected, "Source provenance changed: " + section)
        verified(run_dir, config[section]["source"], expected)
    verified(run_dir, "src/gatl_gf256.py", plan["gf256_sha256"])
    for section in ("profiles", "authentication"):
        verified(run_dir, config[section]["registry"], config[section]["registry_sha256"])
    checked(config["authentication"]["registry_sha256"] == plan["authenticated_registry_sha256"], "Registry changed.")
    verified(run_dir, config["kem"]["backend_manifest"], plan["backend_manifest_sha256"])
    proposal_path = verified(run_dir, config["pilot"]["proposal"], design["proposal_sha256"])
    proposal = json.loads(proposal_path.read_bytes())
    for design_key, proposal_key in (("replicates", "independent_replicates"),
                                    ("latency_n", "latency_blocks_per_replicate"),
                                    ("loss_n", "loss_trials_per_scenario_per_replicate"),
                                    ("budget_n", "budget_trials_per_budget_per_replicate")):
        checked(design[design_key] == proposal[proposal_key], "Final sampling differs from pilot proposal.")
    schedule = json.loads(verified(run_dir, manifest["schedule_file"], manifest["schedule_sha256"]).read_bytes())
    checked(schedule == controller.tasks(trace, plan, design), "Saved schedule does not regenerate.")
    tasks = {controller.task_id(task): task for task in schedule}
    checked(len(tasks) == len(schedule) == manifest["blocks"], "Duplicate or missing scheduled block.")
    checked(set(path.name for path in directory.glob("segment_*")) == set(manifest["segments"]),
            "Segment list changed.")
    environments = []
    for segment_name, artifacts in manifest["segments"].items():
        segment = inside(directory, segment_name)
        checked({path.name for path in segment.iterdir() if path.is_file()} == set(artifacts), "Segment contents changed.")
        for name, digest in artifacts.items():
            verified(segment, name, digest)
        environments.append(json.loads((segment / "started.json").read_bytes()))
    rows, seen = [], set()
    family_counts, file_counts, tails = Counter(), {}, []
    for relative, item in manifest["files"].items():
        path = verified(directory, relative, item["sha256"])
        segment_id = path.parent.name.removeprefix("segment_")
        checked(path.name == "blocks.jsonl" and path.parent.name in manifest["segments"], "Unexpected journal location.")
        checked("fatal.json" not in manifest["segments"][path.parent.name], "Fatal attempt cannot enter analysis.")
        previous, blocks = "0" * 64, 0
        with path.open("rb") as handle:
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    tails.append({"path": path.name, "segment": path.parent.name, "offset": offset,
                                  "bytes": len(line), "sha256": sha(line),
                                  "action": "preserve_not_count_incomplete_block"})
                    break
                envelope = json.loads(line)
                digest = envelope.pop("sha256")
                checked(digest == sha(canonical(envelope)) and envelope["previous"] == previous, "Broken journal chain.")
                task_key = envelope["task_id"]
                checked(task_key in tasks and task_key not in seen, "Duplicate/unknown observed block.")
                task = tasks[task_key]
                block_rows = envelope["rows"]
                controller.validate_rows(block_rows, task, trace, plan, design)
                record = task["record"]
                for row in block_rows:
                    checked(row["design_id"] == manifest["design_id"] and row["segment_id"] == segment_id
                            and row["is_final_benchmark"] is True and row["trace_phase"] == "benchmark", "Row provenance changed.")
                    expected_latency = task["family"] == "primary" and record["scenario_id"] == "iid_p20" and record["trial_id"] < design["latency_n"]
                    expected_loss = task["family"] == "primary" and record["trial_id"] < design["loss_n"]
                    checked(row["latency_member"] is expected_latency and row["loss_member"] is expected_loss,
                            "Latency/loss membership mismatch.")
                    row.update(task_id=task_key, block_index_in_segment=blocks)
                    rows.append(row)
                    family_counts[task["family"]] += 1
                seen.add(task_key)
                previous, blocks = digest, blocks + 1
        checked(blocks == item["blocks"] and blocks * 7 == item["rows"] and previous == item["last_hash"],
                "Journal counts or final chain hash mismatch.")
        file_counts[relative] = blocks
    checked(seen == set(tasks) and len(rows) == manifest["rows"] and dict(family_counts) == manifest["rows_by_family"],
            "Incomplete observation coverage.")
    checked(sorted(tails, key=lambda item: item["segment"]) == sorted(manifest["incomplete_journal_tails_preserved"], key=lambda item: item["segment"]),
            "Unexpected incomplete journal tail.")
    frame = pd.DataFrame(rows)
    del rows
    latency = frame[frame["latency_member"]]
    loss = frame[frame["loss_member"]]
    checked(all(latency[latency["method"] == method].shape[0] == design["replicates"] * design["latency_n"] for method in trace.METHODS),
            "Incorrect final latency sample size.")
    for scenario in plan["scenarios"]:
        for method in trace.METHODS:
            checked(len(loss[(loss["scenario_id"] == scenario["id"]) & (loss["method"] == method)])
                    == design["replicates"] * design["loss_n"], "Incorrect final reliability sample size.")
    return frame, manifest, design, plan, trace, environments

def wilson(successes, count, confidence=0.95):
    checked(type(count) is int and count > 0 and type(successes) is int and 0 <= successes <= count, "Invalid binomial counts.")
    critical = statistics.NormalDist().inv_cdf((1 + confidence) / 2)
    proportion = successes / count
    denominator = 1 + critical ** 2 / count
    center = (proportion + critical ** 2 / (2 * count)) / denominator
    radius = critical * math.sqrt(proportion * (1 - proportion) / count + critical ** 2 / (4 * count ** 2)) / denominator
    lower = 0.0 if successes == 0 else max(0.0, center - radius)
    upper = 1.0 if successes == count else min(1.0, center + radius)
    return lower, upper

def descriptive(values):
    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]
    if not len(values):
        return {"n": 0, "mean": None, "sd": None, "median": None, "p95": None, "p99": None, "minimum": None, "maximum": None}
    return {"n": len(values), "mean": float(values.mean()), "sd": float(values.std(ddof=1)) if len(values) > 1 else None,
            "median": float(np.median(values)), "p95": float(np.quantile(values, .95)), "p99": float(np.quantile(values, .99)),
            "minimum": float(values.min()), "maximum": float(values.max())}

def block_intervals(frame, values, protocol, label, block_length=None):
    values = np.asarray(values, dtype=float)
    checked(len(frame) == len(values), "Bootstrap alignment mismatch.")
    length = protocol["block_length"] if block_length is None else block_length
    seed = int.from_bytes(hashlib.sha256(canonical([protocol["seed"], label, length])).digest()[:16], "big")
    generator = np.random.Generator(np.random.PCG64(seed))
    strata = []
    frame = frame.reset_index(drop=True)
    for positions in frame.groupby(["replicate", "segment_id"], sort=True).indices.values():
        ordered = np.asarray(sorted(positions, key=lambda index: frame.iloc[index]["trial_id"]), dtype=int)
        trials = frame.iloc[ordered]["trial_id"].to_numpy(dtype=int)
        splits = np.flatnonzero(np.diff(trials) != 1) + 1
        strata.extend(part for part in np.split(ordered, splits) if len(part))
    estimates, valid = [], 0
    resamples = protocol["resamples"]
    for batch_start in range(0, resamples, 100):
        batch_size = min(100, resamples - batch_start)
        selected = []
        for positions in strata:
            size = len(positions)
            local_length = min(length, size)
            starts = generator.integers(0, size, size=(batch_size, math.ceil(size / local_length)))
            indices = (starts[:, :, None] + np.arange(local_length)) % size
            selected.append(positions[indices.reshape(batch_size, -1)[:, :size]])
        sample = values[np.concatenate(selected, axis=1)]
        sample = sample[np.isfinite(sample).any(axis=1)]
        valid += len(sample)
        if len(sample):
            estimates.append(np.column_stack((np.nanmean(sample, axis=1), np.nanmedian(sample, axis=1),
                                               np.nanquantile(sample, .95, axis=1))))
    result = {"ci_method": "stratified_circular_block_percentile", "block_length": length,
              "bootstrap_valid": valid, "bootstrap_requested": resamples,
              "strata": len(strata), "strata_shorter_than_block": sum(len(part) < length for part in strata)}
    if valid < .95 * resamples:
        bounds = [[None] * 3, [None] * 3]
    else:
        alpha = (1 - protocol["confidence"]) / 2
        bounds = np.quantile(np.concatenate(estimates), [alpha, 1 - alpha], axis=0).tolist()
    for index, name in enumerate(("mean", "median", "p95")):
        result[name + "_ci_low"], result[name + "_ci_high"] = bounds[0][index], bounds[1][index]
    return result

def aligned(frame, first, second):
    keys = ["replicate", "trial_id", "scenario_id"]
    left = frame[frame["method"] == first].sort_values(keys).reset_index(drop=True)
    right = frame[frame["method"] == second].sort_values(keys).reset_index(drop=True)
    checked(left[keys].equals(right[keys]) and len(left) > 0, "Unpaired observations.")
    checked(left["segment_id"].equals(right["segment_id"]), "Methods from different execution segments.")
    return left, right

def analyse(frame, design, plan, trace, protocol):
    latency = frame[frame["latency_member"]].copy()
    loss = frame[frame["loss_member"]].copy()
    timed, per_replicate, reliability, budget_results, component_results, memory_results = [], [], [], [], [], []
    for method in trace.METHODS:
        selected = latency[latency["method"] == method].sort_values(["replicate", "trial_id"]).reset_index(drop=True)
        for condition, metric in (("all", "transport_processing_ns"), ("failure", "transport_processing_ns"),
                                  ("successful_release", "successful_transport_until_release_ns")):
            values = selected[metric].to_numpy(dtype=float) / 1e6
            if condition == "failure":
                values[selected["success"].to_numpy(dtype=bool)] = np.nan
            entry = {"method": method, "condition": condition, "metric": metric, "unit": "ms", **descriptive(values)}
            if entry["n"]:
                entry.update(block_intervals(selected, values, protocol, [method, condition]))
            timed.append(entry)
        for replicate, part in selected.groupby("replicate", sort=True):
            per_replicate.append({"method": method, "replicate": int(replicate),
                                  "successes_in_latency_subset": int(part["success"].sum()),
                                  **descriptive(part["transport_processing_ns"].to_numpy(dtype=float) / 1e6)})
    for scenario in plan["scenarios"]:
        for method in trace.METHODS:
            part = loss[(loss["scenario_id"] == scenario["id"]) & (loss["method"] == method)]
            successes, count = int(part["success"].sum()), len(part)
            lower, upper = wilson(successes, count)
            expected = trace.exact_success(method, scenario)
            reliability.append({"method": method, "scenario_id": scenario["id"], "n": count, "successes": successes,
                                "failures": count - successes, "observed": successes / count, "ci_low": lower, "ci_high": upper,
                                "analytical_not_measured": expected, "observed_minus_analytical": successes / count - expected,
                                "analytical_inside_pointwise_ci": lower - 1e-12 <= expected <= upper + 1e-12})
    for (budget, method), part in frame[frame["family"] == "budget"].groupby(["budget", "method"], sort=True):
        budget = int(budget)
        allocation = plan["byte_budget"]["allocations"][str(budget)][method]
        successes, count = int(part["success"].sum()), len(part)
        lower, upper = wilson(successes, count)
        checked(count == design["replicates"] * design["budget_n"], "Wrong budget sample size.")
        checked(part["application_bytes"].nunique() == 1 and int(part["application_bytes"].iloc[0]) == allocation["application_bytes"],
                "Scheduled budget bytes changed.")
        budget_results.append({"budget": budget, "method": method, "n": count, "successes": successes,
                               "observed": successes / count, "ci_low": lower, "ci_high": upper,
                               "application_bytes": allocation["application_bytes"], "send_mask": allocation["send_mask"],
                               "analytical_not_measured": allocation["analytical_design_success"],
                               **{"processing_" + key: value for key, value in descriptive(part["transport_processing_ns"] / 1e6).items()}})
    pairs, sensitivity, paired_success = [], [], []
    for baseline, candidate in (("shamir_3_5", "gatl_uniform_3_5"), ("rs_2_5_gateway_check", "gatl_gateway")):
        left, right = aligned(latency, baseline, candidate)
        difference = (right["transport_processing_ns"] - left["transport_processing_ns"]).to_numpy(dtype=float) / 1e6
        entry = {"baseline": baseline, "candidate": candidate, "direction": "candidate_minus_baseline", "unit": "ms",
                 **descriptive(difference), **block_intervals(left, difference, protocol, [baseline, candidate])}
        entry["mean_relative_to_baseline_percent"] = 100 * float(np.mean(difference)) / float(left["transport_processing_ns"].mean() / 1e6)
        entry["ci_is_equivalence_test"] = False
        pairs.append(entry)
        for length in protocol["sensitivity_block_lengths"]:
            sensitivity.append({"baseline": baseline, "candidate": candidate,
                                **block_intervals(left, difference, protocol, [baseline, candidate], length)})
        for scenario in plan["scenarios"]:
            left, right = aligned(loss[loss["scenario_id"] == scenario["id"]], baseline, candidate)
            gain = int((right["success"] & ~left["success"]).sum())
            loss_count = int((left["success"] & ~right["success"]).sum())
            gain_ci, loss_ci = wilson(gain, len(left), .975), wilson(loss_count, len(left), .975)
            paired_success.append({"baseline": baseline, "candidate": candidate, "scenario_id": scenario["id"],
                                   "n": len(left), "candidate_only": gain, "baseline_only": loss_count,
                                   "paired_difference": (gain - loss_count) / len(left),
                                   "ci_low": max(-1.0, gain_ci[0] - loss_ci[1]),
                                   "ci_high": min(1.0, gain_ci[1] - loss_ci[0]),
                                   "ci_method": "Bonferroni_difference_of_two_97.5_percent_Wilson_discordance_intervals",
                                   "no_discordance_is_not_universal_equivalence": True})
    components = frame[frame["family"] == "components"]
    for method, part in components.groupby("method", sort=True):
        for metric in ("share_ns", "reconstruct_ns", "sender_non_share_ns", "receiver_non_reconstruct_ns", "decapsulation_ns"):
            checked(part[metric].notna().all(), "Missing implemented component.")
            component_results.append({"method": method, "metric": metric, "unit": "ms", "condition": "all_trials_actual_work",
                                      **descriptive(part[metric] / 1e6)})
    for method, part in frame[frame["family"] == "memory"].groupby("method", sort=True):
        memory_results.append({"method": method, "metric": "python_traced_peak_bytes", "unit": "bytes",
                               **descriptive(part["python_traced_peak_bytes"])})
    raw_results = []
    for method in trace.METHODS:
        keys = ["replicate", "trial_id", "scenario_id"]
        raw = frame[(frame["family"] == "raw_ablation") & (frame["method"] == method)].sort_values(keys).reset_index(drop=True)
        authenticated = latency[latency["method"] == method].sort_values(keys).reset_index(drop=True)
        checked(raw[keys].equals(authenticated[keys]), "Raw/auth trace alignment differs.")
        checked(raw["success"].equals(authenticated["success"]), "Raw/auth success differs on common erasure trace.")
        differences = (authenticated["transport_processing_ns"] - raw["transport_processing_ns"]) / 1e6
        raw_results.append({"method": method, "unit": "ms", "raw_mean_ms": float(raw["transport_processing_ns"].mean() / 1e6),
                            "authenticated_mean_ms": float(authenticated["transport_processing_ns"].mean() / 1e6),
                            "difference_direction": "authenticated_minus_raw", **descriptive(differences),
                            "interpretation": "descriptive_trace_matched_phase_confounded_not_isolated_HMAC_cost"})
    shared = frame[frame["family"] == "primary"].drop_duplicates("task_id")
    shared_stats = {metric: descriptive(shared[metric] / 1e6) for metric in
                    ("encapsulation_ns_shared_per_block", "codec_batch_setup_ns_shared_per_block")}
    setup_stats = []
    for method, part in latency.groupby("method", sort=True):
        for metric in ("session_setup_ns", "cleanup_ns", "decapsulation_ns"):
            subset = part[part["success"]] if metric == "decapsulation_ns" else part
            setup_stats.append({"method": method, "metric": metric, "condition": "success_only" if metric == "decapsulation_ns" else "all",
                                "unit": "ms", **descriptive(subset[metric] / 1e6)})
    return {"latency": timed, "replicate_latency": per_replicate, "reliability": reliability, "budget": budget_results,
            "paired_latency": pairs, "block_sensitivity": sensitivity, "paired_success": paired_success,
            "components": component_results, "memory": memory_results, "raw_ablation": raw_results,
            "shared_block_timings_ms": shared_stats, "setup_and_decaps": setup_stats}

def export_figures(results, directory, methods):
    import matplotlib.pyplot as plt
    figures = directory / "figures"
    figures.mkdir()
    plt.rcParams.update({"font.size": 9, "pdf.fonttype": 42, "ps.fonttype": 42})
    def save(figure, name):
        figure.tight_layout()
        figure.savefig(figures / (name + ".pdf"), bbox_inches="tight")
        figure.savefig(figures / (name + ".png"), dpi=180, bbox_inches="tight")
        plt.close(figure)
    for category, xfield, name, xlabel in (("reliability", "scenario_id", "iid_reliability", "Synthetic IID packet loss (%)"),
                                          ("budget", "budget", "budget_reliability", "Application-byte budget (B)")):
        figure, axis = plt.subplots(figsize=(7.2, 4.3))
        for method in methods:
            rows = [row for row in results[category] if row["method"] == method
                    and (category == "budget" or row["scenario_id"].startswith("iid_p"))]
            rows.sort(key=lambda row: row[xfield])
            horizontal = [row[xfield] if category == "budget" else int(row[xfield][5:]) for row in rows]
            observed = np.array([100 * row["observed"] for row in rows])
            lower = np.array([100 * row["ci_low"] for row in rows])
            upper = np.array([100 * row["ci_high"] for row in rows])
            line = axis.errorbar(horizontal, observed, yerr=np.maximum(0, [observed - lower, upper - observed]),
                                marker="o", markersize=3, linewidth=1, capsize=2, label=LABELS[method])
            axis.plot(horizontal, [100 * row["analytical_not_measured"] for row in rows], "--",
                      color=line[0].get_color(), linewidth=.8, alpha=.6)
        axis.set(xlabel=xlabel, ylabel="Reconstruction and candidate-key match (%)", ylim=(-2, 102))
        axis.grid(alpha=.2)
        axis.legend(fontsize=7, ncol=2)
        save(figure, name)
    figure, axis = plt.subplots(figsize=(7.2, 4))
    selected = [next(row for row in results["latency"] if row["method"] == method and row["condition"] == "all") for method in methods]
    medians = np.array([row["median"] for row in selected])
    axis.vlines(np.arange(len(methods)), [row["median_ci_low"] for row in selected],
                [row["median_ci_high"] for row in selected])
    axis.plot(np.arange(len(methods)), medians, "o")
    axis.set_xticks(np.arange(len(methods)), [LABELS[method] for method in methods], rotation=25, ha="right")
    axis.set(yscale="log", ylabel="Unconditional transport processing (ms; log scale)")
    axis.grid(alpha=.2, axis="y")
    save(figure, "transport_processing")

def export_tex(results, design, plan, directory, methods):
    tables = directory / "tables"
    tables.mkdir()
    lines = [r"\begin{table*}[t]", r"\centering\footnotesize",
             r"\caption{Authenticated one-shot delivery under synthetic IID 20\% packet loss. Transport processing excludes KEM operations, setup, and network delay. Mean intervals are pointwise block-bootstrap intervals; success intervals are pointwise Wilson intervals. App B is scheduled application data including headers and HMAC, not link-layer wire bytes.}",
             r"\label{tab:measured-gatl-results}", r"\begin{tabular}{lrrrrr}", r"\hline",
             r"Method & Mean ms [95\% CI] & Median ms & P95 ms & Success \% [95\% CI] & App B\\", r"\hline"]
    for method in methods:
        timing = next(row for row in results["latency"] if row["method"] == method and row["condition"] == "all")
        success = next(row for row in results["reliability"] if row["method"] == method and row["scenario_id"] == "iid_p20")
        size = sum(plan["byte_budget"]["packet_sizes"][method].values())
        lines.append(f"{LABELS[method]} & {timing['mean']:.4f} [{timing['mean_ci_low']:.4f}, {timing['mean_ci_high']:.4f}] & "
                     f"{timing['median']:.4f} & {timing['p95']:.4f} & "
                     f"{100*success['observed']:.2f} [{100*success['ci_low']:.2f}, {100*success['ci_high']:.2f}] & {size}" + r"\\")
    lines.extend([r"\hline", r"\end{tabular}", r"\end{table*}"])
    (tables / "benchmark_table.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
    latency_count = design["replicates"] * design["latency_n"]
    loss_count = design["replicates"] * design["loss_n"]
    section = [r"\subsection{Measured Processing and Simulated Delivery}",
               f"The completed evaluation contains {latency_count} latency observations per method and {loss_count} delivery trials per method and scenario, across {design['replicates']} simulation replicates on the same runtime. Pilot and warm-up observations are excluded.",
               r"All reported successes require both reconstructed ciphertext equality and candidate-key equality. This is not an implemented key-confirmation protocol. Loss parameters and arrival orders are synthetic; the model does not measure propagation, fragmentation, retransmission, or an end-to-end deadline.",
               r"\input{tables/benchmark_table.tex}",
               r"Timing intervals use circular block resampling within replicate and execution segment, with a primary block length of 14 and sensitivity lengths 7 and 28. They are conditional on this runtime and weak-dependence assumptions, not simultaneous confidence guarantees or evidence of equivalence. Per-replicate results and sensitivity intervals are retained in the analysis archive."]
    for pair in results["paired_latency"]:
        section.append(f"The paired unconditional processing difference ({LABELS[pair['candidate']]} minus {LABELS[pair['baseline']]}) is "
                       f"{pair['mean']:.4f} ms, with pointwise 95\\% interval [{pair['mean_ci_low']:.4f}, {pair['mean_ci_high']:.4f}] ms. "
                       "These implementation-specific observations do not establish a universal speed advantage.")
    section.extend([r"Raw-versus-authenticated measurements were collected in separate, nonrandomized execution phases with fresh ciphertexts. Their difference is descriptive and cannot be attributed solely to HMAC. Component residuals also include serialization, checking, state handling, and instrumentation.",
                    r"The memory pass reports Python-traced peak allocation during session setup and send/receive, including harness and Python allocations around decapsulation. It excludes preconstructed codecs, prior KEM key setup, and untraced native allocations; it is not RSS or device-memory consumption.",
                    r"Provisioning remains an in-process trusted test setup. No KAT/ACVP certification, active-composition theorem, real-network latency, energy result, cache ablation, or independent external reproduction is established by these measurements."])
    section.extend([r"\begin{figure*}[t]", r"\centering",
                    r"\includegraphics[width=0.48\textwidth]{figures/iid_reliability.pdf}\hfill",
                    r"\includegraphics[width=0.48\textwidth]{figures/budget_reliability.pdf}",
                    r"\caption{Simulated one-shot delivery: IID loss sweep (left) and frozen application-byte budgets at IID 20\% loss (right). Markers are observed ciphertext/key matches with pointwise 95\% Wilson intervals; dashed curves are analytical values, not measurements. Methods with identical received-set rules can overlap. No propagation or size-dependent erasure model is included.}",
                    r"\label{fig:measured-gatl-delivery}", r"\end{figure*}"])
    (directory / "measured_results_section.tex").write_text("\n\n".join(section) + "\n", encoding="utf-8")

def make_zip(destination, members):
    seen = set()
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
        for path, relative in members:
            checked(relative not in seen, "Duplicate archive member.")
            seen.add(relative)
            archive.write(path, relative)
