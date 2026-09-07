def build_profiles(field):
    common_nodes = ["G1", "L1", "L2", "E1", "E2"]
    redundant_nodes = ["G1", "G2", "L2", "E1", "E2"]

    return {
        "gatl_uniform_3_5": {
            "nodes": common_nodes[:],
            "matrix": [
                [1, point, field.gf_mul(point, point)]
                for point in range(1, 6)
            ],
            "row_to_node": common_nodes[:],
            "target": [1, 0, 0],
            "rule": {"kind": "threshold", "threshold": 3},
            "evaluation_points": [1, 2, 3, 4, 5],
            "scope": "primary_comparison",
            "payload_order": "row_index_then_byte_index",
        },
        "gatl_gateway": {
            "nodes": common_nodes[:],
            "matrix": [[1, 1], [0, 1], [0, 1], [0, 1], [0, 1]],
            "row_to_node": common_nodes[:],
            "target": [1, 0],
            "rule": {
                "kind": "all_groups_present",
                "groups": [["G1"], ["L1", "L2", "E1", "E2"]],
            },
            "scope": "primary_comparison",
            "payload_order": "row_index_then_byte_index",
        },
        "gatl_gateway_redundant": {
            "nodes": redundant_nodes[:],
            "matrix": [[1, 1], [1, 1], [0, 1], [0, 1], [0, 1]],
            "row_to_node": redundant_nodes[:],
            "target": [1, 0],
            "rule": {
                "kind": "all_groups_present",
                "groups": [["G1", "G2"], ["L2", "E1", "E2"]],
            },
            "scope": "policy_redundancy_variant",
            "payload_order": "row_index_then_byte_index",
        },
    }

def _received_nodes(profile, received_nodes):
    ordered = list(received_nodes)
    received = set(ordered)

    if len(received) != len(ordered):
        raise ValueError("Duplicate node identifiers are not allowed here.")

    if not received <= set(profile["nodes"]):
        raise ValueError("Unknown node identifier.")

    return received

def policy_allows(profile, received_nodes):
    received = _received_nodes(profile, received_nodes)
    rule = profile["rule"]

    if rule["kind"] == "threshold":
        return len(received) >= rule["threshold"]

    if rule["kind"] == "all_groups_present":
        return all(
            received.intersection(group) for group in rule["groups"]
        )

    raise ValueError("Unknown policy kind.")

def rows_for_nodes(profile, received_nodes):
    received = _received_nodes(profile, received_nodes)

    indices = [
        index for index, node in enumerate(profile["row_to_node"])
        if node in received
    ]

    return indices, [profile["matrix"][index][:] for index in indices]
