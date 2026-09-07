from collections.abc import Mapping

def _buffer(value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("Payload must be bytes-like.")
    return bytes(value)

def _length(value):
    if type(value) is not int:
        raise TypeError("Length must be an integer, not bool.")
    if value <= 0:
        raise ValueError("Length must be positive.")
    return value

def _received(payloads, nodes, block_length):
    if not isinstance(payloads, Mapping):
        raise TypeError("Expected node-to-payload mapping.")
    if not set(payloads) <= set(nodes):
        raise ValueError("Unknown node.")

    result = {}
    for node in nodes:
        if node in payloads:
            data = _buffer(payloads[node])
            if len(data) != block_length:
                raise ValueError("Invalid received block length.")
            result[node] = data

    return result

def _combine(field, weights, blocks):
    if not blocks or len(weights) != len(blocks):
        raise ValueError("Invalid weights/blocks.")

    length = len(blocks[0])
    if any(len(block) != length for block in blocks):
        raise ValueError("Unequal block lengths.")

    output = bytearray(length)
    for weight, block in zip(weights, blocks):
        if weight == 0:
            continue
        for byte_index, value in enumerate(block):
            output[byte_index] ^= field.gf_mul(weight, value)

    return bytes(output)

def _inverse(field, rows):
    size = len(rows)
    if not size or any(len(row) != size for row in rows):
        raise ValueError("Expected nonempty square matrix.")

    augmented = [
        list(row) + [
            int(column == index) for column in range(size)
        ]
        for index, row in enumerate(rows)
    ]

    reduced, pivots = field._rref(augmented, size)
    if len(pivots) != size:
        raise ValueError("Singular decoding matrix.")

    return [row[size:] for row in reduced]

class ReplicaCodec:
    def __init__(self, nodes):
        self.nodes = tuple(nodes)
        if not self.nodes or len(set(self.nodes)) != len(self.nodes):
            raise ValueError("Invalid destinations.")

    def share(self, payload):
        payload = _buffer(payload)
        _length(len(payload))
        return {node: payload for node in self.nodes}

    def reconstruct_raw(self, payloads, expected_length):
        received = _received(
            payloads, self.nodes, _length(expected_length)
        )
        return next(iter(received.values()), None)

class ShamirCodec:
    def __init__(self, field, sharing, profile):
        self.field = field
        self.encoder = sharing.LSSSCodec(field, profile)
        self.nodes = self.encoder.nodes
        self.points = tuple(profile["evaluation_points"])
        self.threshold = len(profile["target"])

        expected = tuple(
            tuple(
                field.gf_pow(point, degree)
                for degree in range(self.threshold)
            )
            for point in self.points
        )

        if (
            len(self.points) != len(self.nodes)
            or 0 in self.points
            or len(set(self.points)) != len(self.points)
            or self.encoder.matrix != expected
            or tuple(profile["row_to_node"]) != self.nodes
        ):
            raise ValueError(
                "Not the declared polynomial threshold profile."
            )

    def share(self, payload):
        return self.encoder.share(payload)

    def reconstruct_raw(self, payloads, expected_length):
        received = _received(
            payloads, self.nodes, _length(expected_length)
        )
        if len(received) < self.threshold:
            return None

        selected = list(received)[:self.threshold]
        points = [
            self.points[self.nodes.index(node)]
            for node in selected
        ]

        weights = []
        for index, point in enumerate(points):
            numerator, denominator = 1, 1

            for other_index, other_point in enumerate(points):
                if index != other_index:
                    numerator = self.field.gf_mul(
                        numerator, other_point
                    )
                    denominator = self.field.gf_mul(
                        denominator, point ^ other_point
                    )

            weights.append(
                self.field.gf_mul(
                    numerator, self.field.gf_inv(denominator)
                )
            )

        return _combine(
            self.field,
            weights,
            [received[node] for node in selected]
        )

class RSCodec:
    def __init__(self, field, nodes, source_blocks, gateway=None):
        self.field = field
        self.nodes = tuple(nodes)
        self.source_blocks = source_blocks
        self.gateway = gateway

        if (
            type(source_blocks) is not int
            or not 1 <= source_blocks <= len(self.nodes) <= 255
            or len(set(self.nodes)) != len(self.nodes)
        ):
            raise ValueError("Invalid RS dimensions.")

        if gateway is not None and (
            gateway not in self.nodes or source_blocks != 2
        ):
            raise ValueError(
                "This gateway checker requires RS(2,n)."
            )

        self.points = tuple(range(1, len(self.nodes) + 1))

        vandermonde = [
            [
                field.gf_pow(point, degree)
                for degree in range(source_blocks)
            ]
            for point in self.points
        ]

        basis_inverse = _inverse(
            field, vandermonde[:source_blocks]
        )
        columns = list(zip(*basis_inverse))

        self.generator = tuple(
            tuple(field.gf_dot(row, column) for column in columns)
            for row in vandermonde
        )

    def share(self, payload):
        payload = _buffer(payload)
        length = _length(len(payload))
        block_length = (
            length + self.source_blocks - 1
        ) // self.source_blocks

        padded = payload + bytes(
            self.source_blocks * block_length - length
        )
        blocks = [
            padded[index * block_length:(index + 1) * block_length]
            for index in range(self.source_blocks)
        ]

        return {
            node: _combine(self.field, row, blocks)
            for node, row in zip(self.nodes, self.generator)
        }

    def reconstruct_raw(self, payloads, expected_length):
        length = _length(expected_length)
        block_length = (
            length + self.source_blocks - 1
        ) // self.source_blocks

        received = _received(
            payloads, self.nodes, block_length
        )

        if len(received) < self.source_blocks:
            return None

        if self.gateway is not None and self.gateway not in received:
            return None

        selected = list(received)[:self.source_blocks]
        rows = [
            self.generator[self.nodes.index(node)]
            for node in selected
        ]

        inverse = _inverse(self.field, rows)
        blocks = [received[node] for node in selected]

        padded = b"".join(
            _combine(self.field, weights, blocks)
            for weights in inverse
        )

        return padded[:length]

def build_methods(field, sharing, profiles):
    uniform = profiles["gatl_uniform_3_5"]
    gateway = profiles["gatl_gateway"]
    nodes = tuple(uniform["nodes"])

    if (
        nodes != ("G1", "L1", "L2", "E1", "E2")
        or tuple(gateway["nodes"]) != nodes
    ):
        raise ValueError(
            "Unexpected node ordering for the comparison."
        )

    return {
        "native": ReplicaCodec(("G1",)),
        "replication": ReplicaCodec(nodes),
        "rs_3_5": RSCodec(field, nodes, 3),
        "shamir_3_5": ShamirCodec(field, sharing, uniform),
        "gatl_uniform_3_5": sharing.LSSSCodec(field, uniform),
        "gatl_gateway": sharing.LSSSCodec(field, gateway),
        "rs_2_5_gateway_check": RSCodec(
            field, nodes, 2, gateway="G1"
        ),
    }
