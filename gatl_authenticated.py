import hashlib
import hmac
import json
import math
import secrets
import threading
import time
from collections import namedtuple
from types import MappingProxyType

TAG_BYTES = 32
MAX_PACKET = 4096
MAX_LENGTH = 1088
MAX_SESSIONS = 256
SUITE = b"ML-KEM-768/HMAC-SHA256"
Context = namedtuple("Context", "version suite sender receiver epoch kemkid sid pid length")
Result = namedtuple("Result", "status context payload")
WIRE = {
    "fields": ["domain", "version", "suite", "sender", "receiver", "epoch",
               "kemkid", "sid", "pid", "length", "node", "rows", "payload"],
    "length_prefix_bytes": 4, "integer_order": "big",
    "version_bytes": 2, "sid_bytes": 8, "length_bytes": 4,
    "epoch_bytes": 16, "kemkid_bytes": 32, "pid_bytes": 32,
    "row_index_bytes": 2, "row_index_base": 0, "tag_bytes": TAG_BYTES,
    "identity_encoding": "printable_ASCII_no_spaces_max64",
    "payload_order": "row_index_then_byte_index",
}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")

def freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    return value

def uint(value, width):
    if type(value) is not int or not 0 <= value < 1 << (8 * width):
        raise ValueError("Invalid unsigned integer.")
    return value.to_bytes(width, "big")

def identity(value):
    data = value.encode("ascii")
    if not 1 <= len(data) <= 64 or any(byte < 33 or byte > 126 for byte in data):
        raise ValueError("Invalid identity.")
    return data

def pack_fields(fields):
    return b"".join(uint(len(field), 4) + field for field in fields)

def body(context, node, rows, payload):
    if type(payload) is not bytes or not payload:
        raise ValueError("Expected nonempty bytes payload.")
    if not 1 <= len(rows) <= 16 or tuple(rows) != tuple(sorted(set(rows))):
        raise ValueError("Rows must be unique and increasing.")
    for value, size in ((context.epoch, 16), (context.kemkid, 32), (context.pid, 32)):
        if type(value) is not bytes or len(value) != size:
            raise ValueError("Invalid fixed-width context field.")
    fields = [b"GATL-share", uint(context.version, 2), context.suite,
              identity(context.sender), identity(context.receiver), context.epoch,
              context.kemkid, uint(context.sid, 8), context.pid, uint(context.length, 4),
              identity(node), b"".join(uint(index, 2) for index in rows), payload]
    encoded = pack_fields(fields)
    if len(encoded) + TAG_BYTES > MAX_PACKET:
        raise ValueError("Packet exceeds the application-layer bound.")
    return encoded

def parse(packet):
    if type(packet) is not bytes or not TAG_BYTES < len(packet) <= MAX_PACKET:
        raise ValueError("Invalid packet size/type.")
    encoded, tag = packet[:-TAG_BYTES], packet[-TAG_BYTES:]
    fields, offset = [], 0
    for field_index in range(13):
        if offset + 4 > len(encoded):
            raise ValueError("Truncated length prefix.")
        length = int.from_bytes(encoded[offset:offset + 4], "big")
        offset += 4
        if length > len(encoded) - offset:
            raise ValueError("Truncated field.")
        fields.append(encoded[offset:offset + length])
        offset += length
    if offset != len(encoded):
        raise ValueError("Trailing data.")
    for index, width in ((1, 2), (5, 16), (6, 32), (7, 8), (8, 32), (9, 4)):
        if len(fields[index]) != width:
            raise ValueError("Noncanonical field width.")
    context = Context(int.from_bytes(fields[1], "big"), fields[2],
                      fields[3].decode("ascii"), fields[4].decode("ascii"),
                      fields[5], fields[6], int.from_bytes(fields[7], "big"),
                      fields[8], int.from_bytes(fields[9], "big"))
    if fields[0] != b"GATL-share" or context.version != 1 or context.suite != SUITE:
        raise ValueError("Unsupported domain/version/suite.")
    if not 1 <= context.length <= MAX_LENGTH or not context.sid:
        raise ValueError("Invalid object length/session id.")
    if len(fields[11]) % 2:
        raise ValueError("Invalid row encoding.")
    rows = tuple(int.from_bytes(fields[11][index:index + 2], "big")
                 for index in range(0, len(fields[11]), 2))
    node = fields[10].decode("ascii")
    if body(context, node, rows, fields[12]) != encoded:
        raise ValueError("Noncanonical body.")
    return context, node, rows, fields[12], encoded, tag

class AuthChannel:
    def __init__(self, entry, sender_codec, receiver_codec, sender, receiver, kemkid,
                 clock=time.monotonic):
        identity(sender)
        identity(receiver)
        if type(kemkid) is not bytes or len(kemkid) != 32:
            raise ValueError("kemkid must be a provisioned 32-byte identifier.")
        copied = json.loads(canonical(entry))
        if copied["wire"] != WIRE:
            raise ValueError("Unsupported registry encoding.")
        self.pid = hashlib.sha256(canonical(copied)).digest()
        self.entry = freeze(copied)
        self.epoch = secrets.token_bytes(16)
        self._key = secrets.token_bytes(32)
        self._sender, self._receiver, self._kemkid = sender, receiver, kemkid
        self._tx, self._rx, self._clock = sender_codec, receiver_codec, clock
        self._states, self._sent, self._cache = {}, set(), {}
        self._next_sid, self._closed = 1, False
        self._lock = threading.RLock()

    def _finish(self, state, status):
        state["status"] = status
        state["payloads"].clear()
        state["accepted"].clear()

    def _expire(self, state):
        if state["status"] == "PENDING" and self._clock() >= state["deadline"]:
            self._finish(state, "EXPIRED")

    def _state(self, context):
        state = self._states.get(context.sid)
        if self._closed or state is None or context != state["context"]:
            raise ValueError("Unknown context or closed epoch.")
        return state

    def admit(self, length=1088, ttl=10.0):
        uint(length, 4)
        if not 1 <= length <= MAX_LENGTH:
            raise ValueError("Unsupported object length.")
        if (isinstance(ttl, bool) or not isinstance(ttl, (int, float))
                or not math.isfinite(ttl) or ttl <= 0):
            raise ValueError("Invalid local deadline.")
        with self._lock:
            if self._closed or len(self._states) >= MAX_SESSIONS:
                raise ValueError("Closed/full epoch; provision a fresh epoch.")
            context = Context(1, SUITE, self._sender, self._receiver, self.epoch,
                              self._kemkid, self._next_sid, self.pid, length)
            self._next_sid += 1
            self._states[context.sid] = {
                "context": context, "deadline": self._clock() + ttl,
                "status": "PENDING", "payloads": {}, "accepted": {},
            }
            return context

    def _payload_length(self, node, length):
        if self.entry["coding"]["kind"] == "rs":
            count = self.entry["coding"]["source_blocks"]
            return (length + count - 1) // count
        return len(self.entry["rows_by_node"][node]) * length

    def send(self, context, payload):
        with self._lock:
            state = self._state(context)
            self._expire(state)
            if state["status"] != "PENDING" or context.sid in self._sent:
                raise ValueError("Context is terminal or already used for sharing.")
            if type(payload) is not bytes or len(payload) != context.length:
                raise ValueError("Incorrect sender payload.")
            self._sent.add(context.sid)
            try:
                shares = self._tx.share(payload)
                if set(shares) != set(self.entry["nodes"]):
                    raise ValueError("Codec/registry node mismatch.")
                packets = {}
                for node, data in shares.items():
                    if len(data) != self._payload_length(node, context.length):
                        raise ValueError("Codec/registry length mismatch.")
                    encoded = body(context, node, self.entry["rows_by_node"][node], data)
                    packets[node] = encoded + hmac.digest(self._key, encoded, "sha256")
                self._cache[context.sid] = packets
                return dict(packets)
            except Exception:
                self._finish(state, "ABORTED")
                raise

    def resend(self, context):
        with self._lock:
            self._state(context)
            if context.sid not in self._cache:
                raise ValueError("No original packets to retransmit.")
            return dict(self._cache[context.sid])

    def receive(self, packet):
        try:
            context, node, rows, data, encoded, tag = parse(packet)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            return Result("DROP", None, None)
        with self._lock:
            try:
                state = self._state(context)
            except ValueError:
                return Result("DROP", None, None)
            if state["status"] != "PENDING":
                return Result("DROP", None, None)
            self._expire(state)
            if state["status"] == "EXPIRED":
                return Result("EXPIRED", context, None)
            expected_rows = self.entry["rows_by_node"].get(node)
            if expected_rows is None or rows != tuple(expected_rows):
                return Result("DROP", None, None)
            if len(data) != self._payload_length(node, context.length):
                return Result("DROP", None, None)
            if not hmac.compare_digest(hmac.digest(self._key, encoded, "sha256"), tag):
                return Result("DROP", None, None)
            if node in state["accepted"]:
                if state["accepted"][node] == packet:
                    return Result("DUPLICATE", context, None)
                self._finish(state, "ABORTED")
                return Result("ABORTED", context, None)
            state["accepted"][node] = packet
            state["payloads"][node] = data
            try:
                recovered = self._rx.reconstruct_raw(dict(state["payloads"]), context.length)
                if recovered is not None and (type(recovered) is not bytes
                                               or len(recovered) != context.length):
                    raise ValueError("Incorrect decoder output.")
            except Exception:
                self._finish(state, "ABORTED")
                raise
            self._expire(state)
            if state["status"] == "EXPIRED":
                return Result("EXPIRED", context, None)
            if recovered is None:
                return Result("WAIT", context, None)
            self._finish(state, "COMPLETED")
            return Result("DELIVERED", context, recovered)

    def inspect(self, context):
        with self._lock:
            state = self._state(context)
            self._expire(state)
            return state["status"], tuple(sorted(state["accepted"]))

    def expire_pending(self):
        with self._lock:
            for state in self._states.values():
                self._expire(state)

    def close(self):
        with self._lock:
            self._closed = True
            self._states.clear()
            self._sent.clear()
            self._cache.clear()
            self._key = b""
