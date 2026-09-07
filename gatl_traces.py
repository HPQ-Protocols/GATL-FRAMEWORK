import hashlib
import json
import math
from itertools import product

import numpy as np

NODES = ("G1", "L1", "L2", "E1", "E2")
METHODS = ("native", "replication", "rs_3_5", "shamir_3_5",
           "gatl_uniform_3_5", "gatl_gateway", "rs_2_5_gateway_check")

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def checked_integer(value, lower, upper, label):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("Invalid " + label)
    return value

def probability(value):
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("Probability must be finite and in [0,1].")
    return float(value)

def stream(seed, *labels):
    checked_integer(seed, 0, 2**64 - 1, "seed")
    digest = hashlib.sha256(canonical([seed, *labels])).digest()
    words = [int.from_bytes(digest[offset:offset + 4], "big") for offset in range(0, 32, 4)]
    return np.random.Generator(np.random.PCG64(np.random.SeedSequence(words)))

def residual_losses(scenario):
    if set(scenario) != {"id", "marginal_loss", "risk_groups"}:
        raise ValueError("Unsupported scenario schema.")
    if not isinstance(scenario["id"], str) or not scenario["id"]:
        raise ValueError("Invalid scenario id.")
    if len(scenario["marginal_loss"]) != len(NODES):
        raise ValueError("Five node marginal probabilities required.")
    marginal = [probability(value) for value in scenario["marginal_loss"]]
    group_survival = [1.0] * len(NODES)
    names = set()
    for group in scenario["risk_groups"]:
        if set(group) != {"id", "nodes", "failure_probability"}:
            raise ValueError("Unsupported group schema.")
        if not isinstance(group["id"], str) or not group["id"] or group["id"] in names:
            raise ValueError("Invalid or duplicate group id.")
        names.add(group["id"])
        members = group["nodes"]
        if not members or len(set(members)) != len(members) or not set(members) <= set(NODES):
            raise ValueError("Invalid shared-risk group nodes.")
        risk = probability(group["failure_probability"])
        for node in members:
            group_survival[NODES.index(node)] *= 1.0 - risk
    residual = []
    for target, survival in zip(marginal, group_survival):
        if survival == 0:
            if target != 1:
                raise ValueError("Certain group failure conflicts with target marginal.")
            residual.append(0.0)
            continue
        value = 1.0 - (1.0 - target) / survival
        if value < -1e-12 or value > 1 + 1e-12:
            raise ValueError("Group failure exceeds target marginal loss.")
        residual.append(min(1.0, max(0.0, value)))
    return residual

def policy_allows(method, mask):
    if method not in METHODS:
        raise ValueError("Unknown method.")
    checked_integer(mask, 0, 31, "received mask")
    count = mask.bit_count()
    if method == "native":
        return bool(mask & 1)
    if method == "replication":
        return bool(mask)
    if method in ("gatl_gateway", "rs_2_5_gateway_check"):
        return bool(mask & 1) and count >= 2
    return count >= 3

def joint_distribution(scenario):
    residual = residual_losses(scenario)
    groups = scenario["risk_groups"]
    if len(groups) > 8:
        raise ValueError("Exact enumeration is limited to eight groups.")
    result = [0.0] * 32
    for states in product((False, True), repeat=len(groups)):
        group_weight, forced = 1.0, set()
        for failed, group in zip(states, groups):
            risk = group["failure_probability"]
            group_weight *= risk if failed else 1.0 - risk
            if failed:
                forced.update(group["nodes"])
        for mask in range(32):
            weight = group_weight
            for index, node in enumerate(NODES):
                received = bool(mask & (1 << index))
                if node in forced:
                    weight *= 0.0 if received else 1.0
                else:
                    weight *= 1.0 - residual[index] if received else residual[index]
            result[mask] += weight
    if not math.isclose(sum(result), 1.0, rel_tol=0, abs_tol=1e-12):
        raise ArithmeticError("Joint probabilities do not sum to one.")
    return result

def exact_success(method, scenario, send_mask=31):
    checked_integer(send_mask, 0, 31, "send mask")
    return sum(weight for mask, weight in enumerate(joint_distribution(scenario))
               if policy_allows(method, mask & send_mask))

def balanced_orders(seed, phase, replicate, count):
    rng = stream(seed, phase, replicate, "method_positions")
    result = []
    while len(result) < count:
        base = list(rng.permutation(len(METHODS)))
        for shift in rng.permutation(len(METHODS)):
            rotated = base[int(shift):] + base[:int(shift)]
            result.append([METHODS[int(index)] for index in rotated])
            if len(result) == count:
                break
    return result

def generate(plan, phase, count, replicate=0):
    if phase not in ("warmup", "pilot", "benchmark"):
        raise ValueError("Unknown trace phase.")
    checked_integer(count, 1, 1000000, "trace count")
    checked_integer(replicate, 0, 2**32 - 1, "replicate")
    if tuple(plan["nodes"]) != NODES or tuple(plan["methods"]) != METHODS:
        raise ValueError("Unsupported node/method ordering.")
    scenarios = plan["scenarios"]
    if not scenarios or len({scenario["id"] for scenario in scenarios}) != len(scenarios):
        raise ValueError("Empty or duplicate scenarios.")
    seed = plan["seeds"]["channel"]
    links = stream(seed, phase, replicate, "links").random((count, len(NODES)))
    method_orders = balanced_orders(plan["seeds"]["method_order"], phase, replicate, count)
    arrival_rng = stream(seed, phase, replicate, "arrival_permutations_not_delays")
    scenario_rng = stream(seed, phase, replicate, "scenario_order")
    arrival_orders = [[NODES[int(index)] for index in arrival_rng.permutation(len(NODES))]
                      for trial in range(count)]
    masks = {}
    for scenario in scenarios:
        residual = residual_losses(scenario)
        alive = links >= np.asarray(residual)
        for group in scenario["risk_groups"]:
            failed = stream(seed, phase, replicate, "risk", scenario["id"], group["id"]).random(count)
            failed = failed < group["failure_probability"]
            for node in group["nodes"]:
                alive[:, NODES.index(node)] &= ~failed
        masks[scenario["id"]] = [sum(1 << index for index, value in enumerate(row) if value) for row in alive]
    records = []
    for trial in range(count):
        for scenario_index in scenario_rng.permutation(len(scenarios)):
            scenario_id = scenarios[int(scenario_index)]["id"]
            records.append({
                "phase": phase, "replicate": replicate, "trial_id": trial,
                "scenario_id": scenario_id, "received_mask": masks[scenario_id][trial],
                "arrival_order": list(arrival_orders[trial]), "method_order": list(method_orders[trial]),
            })
    return records

def delivered_nodes(record, method, send_mask=31):
    if method not in METHODS:
        raise ValueError("Unknown method.")
    checked_integer(record["received_mask"], 0, 31, "received mask")
    checked_integer(send_mask, 0, 31, "send mask")
    if len(record["arrival_order"]) != 5 or set(record["arrival_order"]) != set(NODES):
        raise ValueError("Invalid arrival permutation.")
    deployment_mask = 1 if method == "native" else 31
    effective_mask = record["received_mask"] & send_mask & deployment_mask
    return tuple(node for node in record["arrival_order"] if effective_mask & (1 << NODES.index(node)))

def budget_allocation(method, sizes, budget, design_scenario):
    checked_integer(budget, 0, 1000000, "application-byte budget")
    if set(sizes) != ({"G1"} if method == "native" else set(NODES)):
        raise ValueError("Unexpected deployment nodes.")
    for size in sizes.values():
        checked_integer(size, 1, 4096, "serialized packet size")
    candidates = []
    for send_mask in range(32):
        if any(send_mask & (1 << index) and node not in sizes for index, node in enumerate(NODES)):
            continue
        cost = sum(sizes[node] for index, node in enumerate(NODES) if send_mask & (1 << index))
        if cost <= budget:
            success = exact_success(method, design_scenario, send_mask)
            candidates.append((success, -cost, -send_mask, send_mask, cost))
    best = max(candidates)
    return {"send_mask": best[3], "application_bytes": best[4], "analytical_design_success": best[0]}
