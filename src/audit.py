import hashlib
import json

GENESIS = "GENESIS"


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def audit_hash(previous_hash, event):
    payload = canonical_json(event)
    return hashlib.sha256((previous_hash + payload).encode("utf-8")).hexdigest()


def make_entry(item_id, event_type, actor, role, payload, created_at):
    """落账条目的规范内容；事件链与总账链都只对该内容摘要。"""
    return {
        "item_id": item_id,
        "event_type": event_type,
        "actor": actor,
        "role": role,
        "payload": payload,
        "created_at": created_at,
    }


def entry_from_row(row):
    return make_entry(
        row["item_id"],
        row["event_type"],
        row["actor"],
        row["role"],
        row["payload"],
        row["created_at"],
    )


def verify_item(events):
    """按接近事件逐条核对：重算该事件自己的哈希链。"""
    previous = GENESIS
    for position, event in enumerate(events, start=1):
        entry = entry_from_row(event)
        if event["previous_hash"] != previous or audit_hash(previous, entry) != event["event_hash"]:
            return {
                "valid": False,
                "length": len(events),
                "anchor": previous,
                "head_event_id": events[position - 2]["id"] if position >= 2 else None,
                "first_invalid_event_id": event["id"],
                "first_invalid_position": position,
            }
        previous = event["event_hash"]
    return {
        "valid": True,
        "length": len(events),
        "anchor": previous,
        "head_event_id": events[-1]["id"] if events else None,
        "first_invalid_event_id": None,
        "first_invalid_position": None,
    }


def replay_global(rows):
    """从 GENESIS 起按顺序重算整库总账。

    返回两套锚值：
    - recomputed：从 GENESIS 重算得到，任何补写/删行之后的重算锚值都会变化；
    - stored：库内存储的总账链，结构断裂点之前可信，之后一律不采信。
    结构断裂（链位不连续或存储链接不上）单独定位，不影响断裂点之前的对账。
    """
    recomputed = {}
    stored = {}
    previous = GENESIS
    first_invalid_seq = None
    last_consistent_seq = 0
    head_seq = 0
    head_anchor = GENESIS
    for position, row in enumerate(rows, start=1):
        seq = row["seq"]
        anchor = audit_hash(previous, entry_from_row(row))
        link_ok = (
            isinstance(seq, int)
            and seq == position
            and row["global_previous_hash"] == previous
            and row["global_hash"] == anchor
        )
        if link_ok:
            last_consistent_seq = seq
            stored[seq] = row["global_hash"]
        elif first_invalid_seq is None:
            first_invalid_seq = seq if isinstance(seq, int) else position
        if isinstance(seq, int):
            recomputed[seq] = anchor
            head_seq = max(head_seq, seq)
        previous = anchor
    head_anchor = stored.get(head_seq) if head_seq in stored else None
    return {
        "recomputed": recomputed,
        "stored": stored,
        "structurally_valid": first_invalid_seq is None,
        "first_invalid_seq": first_invalid_seq,
        "last_consistent_seq": last_consistent_seq,
        "head_seq": head_seq,
        "head_anchor": head_anchor,
    }


def verify_global(rows):
    replay = replay_global(rows)
    return {
        "valid": replay["structurally_valid"],
        "length": len(rows),
        "head_seq": replay["head_seq"],
        "anchor": replay["head_anchor"] if replay["structurally_valid"] else None,
        "first_invalid_seq": replay["first_invalid_seq"],
    }


def reconcile_ledger(rows, anchors):
    """用监管回执锚值核对整库总账，从最近一致处往后定位分叉。

    anchors: [{"seq": int, "anchor": str}]，监管每季度拿回的回执锚值。
    结构有效区间用库内存储锚值与回执比对；重算锚值用于发现补写导致的分叉。
    """
    replay = replay_global(rows)
    stored = replay["stored"]
    recomputed = replay["recomputed"]

    checks = []
    latest_match_seq = 0
    mismatches = []
    for anchor in sorted(anchors, key=lambda item: item["seq"]):
        seq = anchor["seq"]
        expected = anchor["anchor"]
        actual = stored.get(seq)
        matches = actual is not None and actual == expected
        checks.append({"seq": seq, "expected": expected, "actual": actual, "matches": matches})
        if matches:
            latest_match_seq = max(latest_match_seq, seq)
        else:
            mismatches.append(seq)

    anchor_fork_start = None
    if mismatches:
        tail_mismatch = [seq for seq in mismatches if seq > latest_match_seq]
        if tail_mismatch:
            if latest_match_seq == 0:
                # 无更早的已匹配锚值可参照：从最早不符的回执链位本身查起
                anchor_fork_start = min(tail_mismatch)
            else:
                # 晚于最近一次匹配的锚值对不上：从最近一致处之后开始定位
                anchor_fork_start = latest_match_seq + 1
        else:
            # 较早锚值先对不上：从最早不符的回执处查起
            anchor_fork_start = min(mismatches)

    # 存储结构完整但重算锚值对不上：整库被补写（行都在、链接被重建）；
    # 结构不完整（删行等）时缺失链位本身已经报分叉，不再做补写比对。
    rewrite_fork_start = None
    if replay["structurally_valid"]:
        for seq in sorted(stored):
            if stored[seq] != recomputed[seq]:
                rewrite_fork_start = seq
                break

    candidate_starts = []
    if not replay["structurally_valid"]:
        candidate_starts.append(replay["first_invalid_seq"])
    if anchor_fork_start is not None:
        candidate_starts.append(anchor_fork_start)
    if rewrite_fork_start is not None:
        candidate_starts.append(rewrite_fork_start)
    fork_start_seq = min(candidate_starts) if candidate_starts else None
    valid = (
        replay["structurally_valid"]
        and rewrite_fork_start is None
        and not mismatches
    )

    affected_item_ids = []
    if fork_start_seq is not None:
        seen = set()
        for row in rows:
            if isinstance(row["seq"], int) and row["seq"] >= fork_start_seq and row["item_id"] is not None:
                if row["item_id"] not in seen:
                    seen.add(row["item_id"])
                    affected_item_ids.append(row["item_id"])

    last_consistent_seq = fork_start_seq - 1 if fork_start_seq is not None else replay["head_seq"]
    return {
        "valid": valid,
        "head": {"seq": replay["head_seq"], "anchor": stored.get(replay["head_seq"])},
        "structural": {
            "valid": replay["structurally_valid"],
            "first_invalid_seq": replay["first_invalid_seq"],
        },
        "anchor_checks": checks,
        "last_consistent": {
            "seq": last_consistent_seq,
            "anchor": stored.get(last_consistent_seq, GENESIS),
        },
        "fork_start_seq": fork_start_seq,
        "affected_item_ids": affected_item_ids,
    }
