import secrets
from collections.abc import Mapping

def _buffer(value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("Payload must be bytes, bytearray or memoryview.")
    return bytes(value)

def _length(value):
    if type(value) is not int:
        raise TypeError("Expected length must be an integer, not bool.")
    if value <= 0:
        raise ValueError("Expected length must be positive.")
    return value

class LSSSCodec:
    def __init__(self, field, profile):
        self.field = field
        self.nodes = tuple(profile["nodes"])
        self.matrix = tuple(tuple(row) for row in profile["matrix"])
        self.row_to_node = tuple(profile["row_to_node"])
        self.target = tuple(profile["target"])
        self.dimension = len(self.target)

        if not self.nodes or any(
            not isinstance(node, str) for node in self.nodes
        ):
            raise ValueError("Nodes must be nonempty string identifiers.")

        if len(set(self.nodes)) != len(self.nodes):
            raise ValueError("Duplicate node identifiers.")

        if not self.matrix or len(self.matrix) != len(self.row_to_node):
            raise ValueError("Invalid matrix/row mapping.")

        if set(self.row_to_node) != set(self.nodes):
            raise ValueError("Each declared node must hold at least one row.")

        if (
            not self.target
            or self.target != (1,) + (0,) * (self.dimension - 1)
        ):
            raise ValueError("This codec requires target e1.")

        if any(len(row) != self.dimension for row in self.matrix):
            raise ValueError("Matrix/target dimensions do not match.")

        field.gf_rank(self.matrix)
        field.gf_dot(self.target, self.target)

        if field.gf_solve(self.matrix, self.target) is None:
            raise ValueError("The full row set cannot reconstruct the target.")

        if profile.get("payload_order") != "row_index_then_byte_index":
            raise ValueError("Unsupported payload layout.")

        self.rows_by_node = {
            node: tuple(
                index for index, owner in enumerate(self.row_to_node)
                if owner == node
            )
            for node in self.nodes
        }

    def share(self, payload):
        payload = _buffer(payload)
        length = _length(len(payload))
        mask_width = self.dimension - 1

        masks = secrets.token_bytes(length * mask_width)
        row_buffers = [
            bytearray(length) for row in self.matrix
        ]

        for byte_index, value in enumerate(payload):
            start = byte_index * mask_width
            vector = [value] + list(masks[start:start + mask_width])

            for row_index, row in enumerate(self.matrix):
                row_buffers[row_index][byte_index] = self.field.gf_dot(
                    row, vector
                )

        return {
            node: b"".join(
                bytes(row_buffers[index])
                for index in self.rows_by_node[node]
            )
            for node in self.nodes
        }

    def reconstruct_raw(self, received_payloads, expected_length):
        length = _length(expected_length)

        if not isinstance(received_payloads, Mapping):
            raise TypeError(
                "Received payloads must be a node-to-payload mapping."
            )

        if not set(received_payloads) <= set(self.nodes):
            raise ValueError("Unknown node identifier.")

        received_rows = {}

        for node, payload in received_payloads.items():
            payload = _buffer(payload)
            node_rows = self.rows_by_node[node]

            if len(payload) != len(node_rows) * length:
                raise ValueError(
                    "Received payload length does not match the profile."
                )

            for local_index, row_index in enumerate(node_rows):
                start = local_index * length
                received_rows[row_index] = payload[start:start + length]

        indices = sorted(received_rows)
        rows = [self.matrix[index] for index in indices]
        weights = self.field.gf_solve(rows, self.target)

        if weights is None:
            return None

        recovered = bytearray(length)

        for weight, row_index in zip(weights, indices):
            if weight == 0:
                continue

            for byte_index, value in enumerate(received_rows[row_index]):
                recovered[byte_index] ^= self.field.gf_mul(weight, value)

        return bytes(recovered)
