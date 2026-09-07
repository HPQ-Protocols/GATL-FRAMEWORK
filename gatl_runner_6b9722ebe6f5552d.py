import hashlib
import hmac
import json
import secrets
import time

class TrialError(RuntimeError):
    def __init__(self, row, label):
        super().__init__(label)
        self.row = row

class Meter:
    def __init__(self, target):
        self.target = target
        self.share_ns = self.reconstruct_ns = self.send_ns = self.receive_ns = self.decaps_ns = 0
        self.decaps_calls = 0

    def __getattr__(self, name):
        return getattr(self.target, name)

    def share(self, payload):
        started = time.perf_counter_ns()
        try:
            return self.target.share(payload)
        finally:
            self.share_ns += time.perf_counter_ns() - started

    def reconstruct_raw(self, received, length):
        started = time.perf_counter_ns()
        try:
            return self.target.reconstruct_raw(received, length)
        finally:
            self.reconstruct_ns += time.perf_counter_ns() - started

    def send(self, context, payload):
        started = time.perf_counter_ns()
        try:
            return self.target.send(context, payload)
        finally:
            self.send_ns += time.perf_counter_ns() - started

    def receive(self, packet):
        started = time.perf_counter_ns()
        try:
            return self.target.receive(packet)
        finally:
            self.receive_ns += time.perf_counter_ns() - started

    def decaps(self, secret_key, ciphertext):
        self.decaps_calls += 1
        started = time.perf_counter_ns()
        try:
            return self.target.decaps(secret_key, ciphertext)
        finally:
            self.decaps_ns += time.perf_counter_ns() - started

class RawChannel:
    def __init__(self, auth, entry, sender_codec, receiver_codec, kemkid):
        self.auth, self.entry = auth, entry
        self.tx, self.rx, self._kemkid = sender_codec, receiver_codec, kemkid
        self.context = auth.Context(1, auth.SUITE, "sender-A", "receiver-B", secrets.token_bytes(16),
                                    kemkid, 1, hashlib.sha256(auth.canonical(entry)).digest(), 1088)
        self.pending, self.sent, self.received = True, False, {}

    def admit(self, length=1088):
        if length != 1088:
            raise ValueError("Unsupported raw test length.")
        return self.context

    def send(self, context, payload):
        if not self.pending or self.sent or context != self.context or type(payload) is not bytes or len(payload) != 1088:
            raise ValueError("Invalid raw send.")
        self.sent = True
        return self.tx.share(payload)

    def receive(self, packet):
        if not self.pending:
            return self.auth.Result("DROP", None, None)
        node, data = packet
        if node not in self.entry["nodes"] or node in self.received:
            raise ValueError("Invalid raw node.")
        self.received[node] = data
        recovered = self.rx.reconstruct_raw(dict(self.received), 1088)
        if recovered is None:
            return self.auth.Result("WAIT", self.context, None)
        self.pending = False
        self.received.clear()
        return self.auth.Result("DELIVERED", self.context, recovered)

    def close(self):
        self.pending = False
        self.received.clear()

class Runner:
    def __init__(self, codec_factory, auth, mlkem, kem, trace, entries, plan):
        self.factory, self.auth, self.mlkem, self.kem, self.trace = codec_factory, auth, mlkem, kem, trace
        self.entries = json.loads(auth.canonical(entries))
        self.plan = json.loads(auth.canonical(plan))
        started = time.perf_counter_ns()
        self.public_key, self.secret_key = kem.keygen()
        self.keygen_ns = time.perf_counter_ns() - started
        mlkem.require_bytes(self.public_key, 1184, "public key")
        self.closed = False

    def close(self):
        self.secret_key = b""
        self.closed = True

    def block(self, record, family="primary", budget=None, packet_hook=None):
        if self.closed:
            raise RuntimeError("Runner is closed.")
        if family not in ("primary", "warmup", "components", "budget", "raw_ablation", "selftest"):
            raise ValueError("Unknown measurement family.")
        if (family == "budget") != (budget is not None):
            raise ValueError("Budget family must have exactly one declared budget.")
        if budget is not None and str(budget) not in self.plan["byte_budget"]["allocations"]:
            raise ValueError("Budget is not in frozen plan.")
        if len(record["method_order"]) != 7 or set(record["method_order"]) != set(self.trace.METHODS):
            raise ValueError("Invalid method order.")
        self.trace.checked_integer(record["received_mask"], 0, 31, "mask")
        for method in self.trace.METHODS:
            self.trace.delivered_nodes(record, method)
        started = time.perf_counter_ns()
        ciphertext, sender_key = self.kem.encaps(self.public_key)
        encaps_ns = time.perf_counter_ns() - started
        self.mlkem.require_bytes(ciphertext, 1088, "ciphertext")
        self.mlkem.require_bytes(sender_key, 32, "sender key")
        started = time.perf_counter_ns()
        senders, receivers = self.factory(), self.factory()
        batch_setup_ns = time.perf_counter_ns() - started
        for position, method in enumerate(record["method_order"]):
            send_mask = 1 if method == "native" else 31
            if budget is not None:
                send_mask = self.plan["byte_budget"]["allocations"][str(budget)][method]["send_mask"]
            row = {
                "schema_version": 1, "trace_phase": record["phase"], "replicate": record["replicate"],
                "trial_id": record["trial_id"], "scenario_id": record["scenario_id"], "family": family,
                "method": method, "method_position": position, "budget": budget, "send_mask": send_mask,
                "received_mask": record["received_mask"], "mode": "raw" if family == "raw_ablation" else "authenticated",
                "success": False, "ciphertext_equal": None, "key_equal": None, "outcome": "INCOMPLETE",
                "error_type": None, "error_code": None, "statuses": {}, "decapsulation_calls": None,
                "encapsulation_ns_shared_per_block": encaps_ns, "codec_batch_setup_ns_shared_per_block": batch_setup_ns,
                "session_setup_ns": None, "cleanup_ns": None, "processing_loop_wall_ns": None,
                "send_ns": None, "receive_ns": None, "transport_processing_ns": None,
                "successful_transport_until_release_ns": None, "decapsulation_ns": None,
                "share_ns": None, "reconstruct_ns": None, "sender_non_share_ns": None,
                "receiver_non_reconstruct_ns": None, "solver_ns": None, "combine_ns": None, "mac_only_ns": None,
                "generated_bytes": None, "scheduled_bytes": None, "application_bytes": None,
                "received_bytes": None, "lower_layer_wire_bytes": None, "control_bytes": None,
                "scheduled_packets": None, "receive_calls": 0,
            }
            receiver = None
            started = time.perf_counter_ns()
            try:
                diagnostic = family == "components"
                tx = Meter(senders[method]) if diagnostic else senders[method]
                rx = Meter(receivers[method]) if diagnostic else receivers[method]
                if row["mode"] == "raw":
                    channel = RawChannel(self.auth, self.entries[method], tx, rx, self.mlkem.key_id(self.public_key))
                else:
                    channel = self.auth.AuthChannel(self.entries[method], tx, rx, "sender-A", "receiver-B",
                                                   self.mlkem.key_id(self.public_key), clock=lambda: 0.0)
                channel_meter, kem_meter = Meter(channel), Meter(self.kem)
                receiver = self.mlkem.VerifiedKEMReceiver(channel_meter, kem_meter, self.public_key, self.secret_key)
                context = channel.admit(1088)
                row["session_setup_ns"] = time.perf_counter_ns() - started
                arrivals = self.trace.delivered_nodes(record, method, send_mask)
                started = time.perf_counter_ns()
                packets = channel_meter.send(context, ciphertext)
                if packet_hook is not None:
                    packets = packet_hook(method, dict(packets))
                releases = []
                for node in arrivals:
                    packet = (node, packets[node]) if row["mode"] == "raw" else packets[node]
                    row["receive_calls"] += 1
                    result = receiver.receive(packet)
                    row["statuses"][result.status] = row["statuses"].get(result.status, 0) + 1
                    if result.status == "KEY_CANDIDATE":
                        releases.append(result)
                        row["successful_transport_until_release_ns"] = channel_meter.send_ns + channel_meter.receive_ns
                row["processing_loop_wall_ns"] = time.perf_counter_ns() - started
                row.update(send_ns=channel_meter.send_ns, receive_ns=channel_meter.receive_ns,
                           transport_processing_ns=channel_meter.send_ns + channel_meter.receive_ns,
                           decapsulation_ns=kem_meter.decaps_ns, decapsulation_calls=receiver.decapsulation_calls)
                if diagnostic:
                    row.update(share_ns=tx.share_ns, reconstruct_ns=rx.reconstruct_ns,
                               sender_non_share_ns=channel_meter.send_ns - tx.share_ns,
                               receiver_non_reconstruct_ns=channel_meter.receive_ns - rx.reconstruct_ns)
                if set(packets) != set(self.entries[method]["nodes"]) or any(type(data) is not bytes for data in packets.values()):
                    raise ValueError("Invalid outbound buffers.")
                scheduled = [node for index, node in enumerate(self.trace.NODES) if send_mask & (1 << index)]
                row.update(generated_bytes=sum(map(len, packets.values())), scheduled_packets=len(scheduled),
                           scheduled_bytes=sum(len(packets[node]) for node in scheduled),
                           received_bytes=sum(len(packets[node]) for node in arrivals))
                if row["mode"] == "authenticated":
                    row["application_bytes"] = row["scheduled_bytes"]
                    if any(len(packet) != self.plan["byte_budget"]["packet_sizes"][method][node] for node, packet in packets.items()):
                        raise ValueError("Packet size differs from Cell8 plan.")
                if budget is not None and row["scheduled_bytes"] > budget:
                    raise ValueError("Scheduled bytes exceeded budget.")
                if len(releases) == 1:
                    row["ciphertext_equal"] = releases[0].ciphertext == ciphertext
                    row["key_equal"] = hmac.compare_digest(releases[0].candidate_key, sender_key)
                    row["success"] = row["ciphertext_equal"] and row["key_equal"]
                    row["outcome"] = "KEY_CANDIDATE" if row["success"] else "CORRUPT_RECONSTRUCTION"
                if len(releases) > 1 or receiver.decapsulation_calls != len(releases) or kem_meter.decaps_calls != len(releases):
                    raise ValueError("Multiple releases or inconsistent decapsulation counters.")
                expected = self.trace.policy_allows(method, record["received_mask"] & send_mask)
                row["oracle_expected"] = expected
                if row["success"] != expected or (releases and not row["success"]):
                    row["error_code"] = "OBSERVED_RESULT_DIFFERS_FROM_ORACLE"
                    raise ValueError("Observed result differs from reconstruction oracle.")
                if any(value < 0 for key, value in row.items() if key.endswith("_ns") and value is not None):
                    raise ValueError("Negative measured duration.")
            except Exception as error:
                row["outcome"], row["error_type"] = "ERROR", type(error).__name__
                if receiver is not None:
                    row.update(send_ns=channel_meter.send_ns, receive_ns=channel_meter.receive_ns,
                               transport_processing_ns=channel_meter.send_ns + channel_meter.receive_ns,
                               decapsulation_ns=kem_meter.decaps_ns, decapsulation_calls=receiver.decapsulation_calls)
                if row["error_code"] is None:
                    row["error_code"] = "RUNNER_OR_BACKEND_EXCEPTION"
                raise TrialError(row, row["error_code"]) from error
            finally:
                cleanup_started = time.perf_counter_ns()
                if receiver is not None:
                    receiver.close()
                row["cleanup_ns"] = time.perf_counter_ns() - cleanup_started
            yield row
