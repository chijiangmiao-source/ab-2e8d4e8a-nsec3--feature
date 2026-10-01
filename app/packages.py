"""多目标“共同记录 NSEC3 不存在证明”证据包引擎。

值班员打开一份**已通过**的冻结单目标审计后，可提交一个稳定证据包标识与
二至六个同一区域的规范目标名称，要求从**来源审计冻结的完整记录组**中抽出
一小组共同记录，使每个目标在该子集上仍各自构成完整的 RFC 5155 §8.9
不存在证明（CE + 下一层名称覆盖 + 通配符覆盖）。

关键约束（对应任务规约）：

- 来源审计的区域、盐值、迭代次数与**完整记录组**被原样冻结进证据包，
  证据包结论不依赖来源审计日后的任何变化（来源审计本身也绝不被改写）；
- 来源审计不存在、结论非通过、目标越区/即顶点、目标数量越界、重复目标
  一律 rejected；证据包标识复用但改换来源或目标返回冲突，不覆盖原结论；
- 候选子集**逐目标重新调用** verifier.evaluate_target：最近存在祖先、
  下一层名称、通配符覆盖全部重算——增加/删除一条记录都可能改变最近
  存在祖先，从而使其余记录角色变化，因此绝不允许把各目标在完整记录组
  上各自的单条证明简单拼接后宣称最优；
- 最优裁决：先比较**记录数最少**，记录数相同再按所选记录 owner 哈希
  升序序列做字典序稳定裁决。

完备性说明：在通过区间一致性校验的记录组中，环形半开区间互不重叠，任一
非 owner 哈希恰被一条记录覆盖。因此对某目标选定“最近存在祖先”后，其
下一层名称与 *.CE 的覆盖记录即被几何唯一确定。枚举只需让每个目标在其
存在于记录组中的各层祖先里选择 CE（共至多“目标数 × 祖先深度”种组合，
实际深度很小），对每个组合取记录并集，再逐目标完整复算裁决。
"""

from __future__ import annotations

import hashlib
import json

from .nsec3 import (
    AuditError,
    ancestor_chain,
    is_subdomain,
    normalise_domain,
    nsec3_hash,
)
from .verifier import (
    REJECT,
    PASS,
    _Ctx,
    _h2int,
    check_interval_conflicts,
    evaluate_target,
    parse_records,
    ring_interval,
)

MAX_TARGETS = 6
MIN_TARGETS = 2
# 防御性上限：正常深度/目标数下远不可达；超过说明输入异常，拒绝而非乱裁
_COMBO_CAP = 1_000_000

ROLE_CN = "ce"
ROLE_NC = "nc"
ROLE_WC = "wc"


def package_fingerprint(payload: dict) -> str:
    """证据包载荷指纹：来源审计标识/来源指纹/目标序列任一改变即不同。"""
    key = {
        "kind": "nsec3-evidence-package-v1",
        "package_id": payload.get("package_id", ""),
        "source_audit_id": payload.get("source_audit_id", ""),
        "source_fingerprint": payload.get("source_fingerprint", ""),
        "targets": list(payload.get("targets", [])),
    }
    return hashlib.sha256(
        json.dumps(key, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def _frozen_record_view(r) -> dict:
    o, n = _h2int(r.owner_hash), _h2int(r.next_hash)
    return {
        "ref": r.ref,
        "owner_hash": r.owner_hash,
        "next_hash": r.next_hash,
        "types": list(r.types),
        "opt_out": r.opt_out,
        "wrap_direction": "wrap" if o > n else "no-wrap",
    }


def _coverers(records, h_int) -> list[str]:
    """返回区间几何上覆盖给定哈希的记录 ref（一致链中至多一条）。"""
    out = []
    for r in records:
        if not r.owner_hash or not r.next_hash:
            continue
        inside, _ = ring_interval(_h2int(r.owner_hash), _h2int(r.next_hash), h_int)
        if inside:
            out.append(r.ref)
    return out


def _ce_options(target, zone, salt, iterations, records, owner_map):
    """枚举目标在完整记录组上所有可行的 CE 选项。

    每项给出：CE 名称/哈希/记录 ref，下一层名称及其覆盖记录 ref，通配符
    名及其覆盖记录 ref。NC 或 *.CE 自身即 owner、或缺覆盖的选项几何上
    不可行（区间成员关系不随子集变化，换子集也补不出来），直接剔除。
    """
    chain = ancestor_chain(target, zone)
    options = []
    for idx, name in enumerate(chain):
        h_ce = nsec3_hash(name, salt, iterations)
        ce_rec = owner_map.get(h_ce)
        if ce_rec is None:
            continue  # 该层祖先不存在，不能充当 CE
        nc_name = chain[idx - 1] if idx > 0 else None
        h_nc = nsec3_hash(nc_name, salt, iterations) if nc_name else None
        wc_name = "*." + name
        h_wc = nsec3_hash(wc_name, salt, iterations)
        if h_nc is not None and h_nc in owner_map:
            continue  # 下一层名称自身存在，与“不存在”矛盾
        if h_wc in owner_map:
            continue  # 通配符自身存在，可能展开
        nc_refs = _coverers(records, _h2int(h_nc)) if h_nc is not None else []
        wc_refs = _coverers(records, _h2int(h_wc))
        if not nc_refs or not wc_refs:
            continue
        options.append({
            "ce_name": name, "nc_name": nc_name, "wc_name": wc_name,
            "h_ce": h_ce, "h_nc": h_nc, "h_wc": h_wc,
            "ce_ref": ce_rec.ref,
            "nc_ref": nc_refs[0],
            "wc_ref": wc_refs[0],
        })
    return options


def _owner_seq(records_by_ref, refs) -> tuple[str, ...]:
    return tuple(sorted(records_by_ref[r].owner_hash for r in refs))


def build_package(payload: dict, source_record: dict | None) -> dict:
    """对证据包提交执行审计，返回可冻结的完整结论字典（纯函数）。

    source_record 为存储层中来源审计的冻结记录 {"result", "fingerprint"}；
    为 None 表示来源标识在库中不存在。
    """
    ctx = _Ctx()
    payload = payload or {}

    package_id = str(payload.get("package_id", "")).strip()
    if not package_id or len(package_id) > 128 or any(c.isspace() for c in package_id):
        ctx.fail("BAD_PACKAGE_ID", "证据包标识须为非空且不含空白的字符串（≤128 字符）")

    source_audit_id = str(payload.get("source_audit_id", "")).strip()
    if not source_audit_id:
        ctx.fail("BAD_SOURCE_AUDIT_ID", "必须给出作为证据来源的冻结审计标识")

    result: dict = {
        "kind": "nsec3-evidence-package",
        "package_id": package_id,
        "source_audit_id": source_audit_id,
        "source_fingerprint": "",
        "zone": "",
        "salt": "-",
        "iterations": 0,
        "algorithm": "SHA-1",
        "targets": [],
        "verdict": REJECT,
        "frozen_source_records": [],
        "total_source_records": 0,
        "selected": [],
        "selected_count": 0,
        "unused": [],
        "shared": [],
        "targets_detail": [],
        "candidate_stats": {"evaluated": 0, "feasible": 0},
        "checks": ctx.checks,
        "errors": ctx.errors,
    }

    # ── 来源审计必须存在且结论为通过 ─────────────────────────────
    source = None
    if source_record is not None:
        source = source_record.get("result")
        result["source_fingerprint"] = source_record.get("fingerprint", "")
    if source is None:
        ctx.fail(
            "SOURCE_NOT_FOUND",
            f"来源审计 {source_audit_id} 不存在：证据包只能从已冻结的审计抽取记录",
        )
        return result
    if source.get("verdict") != PASS:
        ctx.fail(
            "SOURCE_NOT_PASSED",
            f"来源审计 {source_audit_id} 结论为 {source.get('verdict')}，"
            "只有通过的审计才能作为共同记录证据包的来源",
        )
        return result

    zone = source["zone"]
    salt = source["salt"]
    iterations = source["iterations"]
    result["zone"] = zone
    result["salt"] = salt
    result["iterations"] = iterations

    # ── 冻结来源完整记录组（重新解析校验，ref 沿用冻结次序 R1..Rn）──
    src_ctx = _Ctx()
    records = parse_records(
        [
            {
                "owner_hash": r.get("owner_hash", ""),
                "next_hash": r.get("next_hash", ""),
                "types": list(r.get("types", [])),
                "opt_out": r.get("opt_out", False),
            }
            for r in source.get("records", [])
        ],
        src_ctx,
    )
    check_interval_conflicts(records, src_ctx)
    frozen_view = [_frozen_record_view(r) for r in records]
    result["frozen_source_records"] = frozen_view
    result["total_source_records"] = len(frozen_view)
    if src_ctx.errors:
        for e in src_ctx.errors:
            ctx.fail("SOURCE_RECORDS_INVALID", f"来源冻结记录组异常：{e['message']}")
        return result

    # ── 目标列表：2..6 个、规范、同区、非顶点、去重 ───────────────
    raw_targets = payload.get("targets", [])
    if not isinstance(raw_targets, list):
        ctx.fail("BAD_TARGETS", "targets 必须是名称数组")
        raw_targets = []
    targets: list[str] = []
    seen_targets: set[str] = set()
    for item in raw_targets:
        try:
            t = normalise_domain(str(item))
        except AuditError as exc:
            ctx.fail("BAD_TARGET", f"目标 {item!r} 非法：{exc}")
            continue
        if t in seen_targets:
            ctx.fail("DUP_TARGET", f"目标 {t} 重复：共同记录证据包不接受重复目标")
            continue
        seen_targets.add(t)
        if not is_subdomain(t, zone):
            ctx.fail("OUT_OF_ZONE", f"目标 {t} 不在来源审计区域 {zone} 内")
        elif t == zone:
            ctx.fail("TARGET_IS_APEX", f"目标 {t} 即区域顶点，不可能为 NXDOMAIN")
        targets.append(t)
    if raw_targets and len(raw_targets) < MIN_TARGETS:
        ctx.fail("TOO_FEW_TARGETS", f"证据包须至少给出 {MIN_TARGETS} 个目标")
    if len(raw_targets) > MAX_TARGETS:
        ctx.fail("TOO_MANY_TARGETS", f"证据包至多接受 {MAX_TARGETS} 个目标")
    result["targets"] = targets

    if ctx.errors:
        return result

    records_by_ref = {r.ref: r for r in records}
    owner_map = {r.owner_hash: r for r in records if r.owner_hash}

    # ── 完整冻结记录组必须能证明每个目标（否则任何子集都不可能）─────
    single_refs: dict[str, set[str]] = {}
    unprovable = False
    for t in targets:
        ev = evaluate_target(t, zone, salt, iterations, records)
        if not ev.passed:
            unprovable = True
            for e in ev.errors:
                ctx.fail(
                    "TARGET_UNPROVABLE",
                    f"目标 {t} 即使使用来源完整记录组也不成立：[{e['code']}] {e['message']}",
                )
        else:
            # 各目标在完整记录组上各自所需的记录（“简单拼接”基线）
            single_refs[t] = {
                ref for ref, role in ev.roles.items()
                if role[ROLE_CN] or role[ROLE_NC] or role[ROLE_WC]
            }
    ctx.check(
        "full-set-all-targets",
        not unprovable,
        ("全部目标在来源完整记录组上复算均通过" if not unprovable
         else "存在目标在来源完整记录组上即无法证明"),
    )
    if unprovable:
        return result

    # ── 构造每个目标的 CE 选项（覆盖记录几何唯一）─────────────────
    options_by_target: dict[str, list[dict]] = {}
    for t in targets:
        opts = _ce_options(t, zone, salt, iterations, records, owner_map)
        feasible = [o for o in opts if o["nc_ref"] and o["wc_ref"]]
        if not feasible:
            ctx.fail("NO_CANDIDATE", f"目标 {t} 不存在任何可行的 CE/覆盖组合")
            return result
        options_by_target[t] = feasible

    # ── 枚举候选并集，逐目标完整复算裁决 ─────────────────────────
    order = sorted(targets, key=lambda t: len(options_by_target[t]))
    best: dict | None = None  # {"refs": frozenset, "seq": tuple, "evals": list}
    seen_unions: set[frozenset] = set()
    stats = {"evaluated": 0, "feasible": 0}

    def consider(refs: frozenset) -> None:
        nonlocal best
        if refs in seen_unions:
            return
        seen_unions.add(refs)
        if best is not None and len(refs) > len(best["refs"]):
            return  # 记录数不可能更优
        stats["evaluated"] += 1
        if stats["evaluated"] > _COMBO_CAP:
            raise _ComboCap()
        sub = [records_by_ref[r] for r in refs]
        evals = [evaluate_target(t, zone, salt, iterations, sub) for t in targets]
        if not all(ev.passed for ev in evals):
            return  # 逐目标复算失败：多出/缺少记录改变了 CE 或覆盖，候选失效
        stats["feasible"] += 1
        seq = _owner_seq(records_by_ref, refs)
        if best is None or len(refs) < len(best["refs"]) or (
            len(refs) == len(best["refs"]) and seq < best["seq"]
        ):
            best = {"refs": refs, "seq": seq, "evals": evals}

    class _ComboCap(Exception):
        pass

    try:
        def dfs(i: int, acc: frozenset) -> None:
            if best is not None and len(acc) > len(best["refs"]):
                return
            if i == len(order):
                consider(acc)
                return
            t = order[i]
            for o in options_by_target[t]:
                triple = {o["ce_ref"], o["nc_ref"], o["wc_ref"]}
                dfs(i + 1, acc | triple)

        dfs(0, frozenset())
    except _ComboCap:
        ctx.fail(
            "CANDIDATE_SPACE_TOO_LARGE",
            f"候选组合数超过上限 {_COMBO_CAP}：来源记录组对该批目标过大，拒绝出具结论",
        )
        return result

    result["candidate_stats"] = stats
    if best is None:
        ctx.fail(
            "NO_COMMON_SUBSET",
            "不存在任何使全部目标同时通过的共同记录子集："
            "不得把各目标各自的证明拼接后宣称共同证明成立",
        )
        return result

    selected_refs = set(best["refs"])
    best_evals = dict(zip(targets, best["evals"]))

    # ── 组装并列展示：每目标三角色 / 共享归属 / 未选用记录 ─────────
    attribution: dict[str, dict[str, list[str]]] = {
        ref: {} for ref in selected_refs
    }  # ref -> {target: [roles]}
    targets_detail = []
    for t in targets:
        ev = best_evals[t]
        used: dict[str, list[str]] = {}
        for ref, role in ev.roles.items():
            if ref not in selected_refs:
                continue
            tags = [k for k, v in role.items() if v and k in (ROLE_CN, ROLE_NC, ROLE_WC)]
            if tags:
                used[ref] = tags
                attribution.setdefault(ref, {})[t] = tags
        ce = ev.closest_encloser or {}
        nc = ev.next_closer or {}
        wc = ev.wildcard or {}
        targets_detail.append({
            "target": t,
            "passed": True,
            "used_refs": sorted(used, key=lambda r: records_by_ref[r].owner_hash),
            "closest_encloser": {
                "name": ce.get("name"), "hash": ce.get("hash"),
                "record_ref": ce.get("record_ref"),
            },
            "next_closer": {"name": nc.get("name"), "hash": nc.get("hash"),
                            "record_refs": sorted(
                                ref for ref, tags in used.items() if ROLE_NC in tags)},
            "wildcard": {"name": wc.get("name"), "hash": wc.get("hash"),
                         "record_refs": sorted(
                             ref for ref, tags in used.items() if ROLE_WC in tags)},
            "roles": {ref: tags for ref, tags in sorted(used.items())},
            "ancestors": ev.ancestors,
            "checks": ev.checks,
        })

    selected = []
    shared = []
    for ref in sorted(selected_refs, key=lambda r: records_by_ref[r].owner_hash):
        view = _frozen_record_view(records_by_ref[ref])
        per_target = attribution.get(ref, {})
        view["serves"] = [
            {"target": t, "roles": tags}
            for t, tags in sorted(per_target.items())
        ]
        view["shared"] = len(per_target) >= 2
        selected.append(view)
        if len(per_target) >= 2:
            shared.append({
                "ref": ref,
                "owner_hash": records_by_ref[ref].owner_hash,
                "served_targets": [
                    {"target": t, "roles": tags}
                    for t, tags in sorted(per_target.items())
                ],
            })

    unused = [
        view for view in frozen_view if view["ref"] not in selected_refs
    ]

    stitched = len(set().union(*single_refs.values())) if single_refs else 0
    result["single_proof_union"] = {
        t: sorted(refs, key=lambda r: records_by_ref[r].owner_hash)
        for t, refs in sorted(single_refs.items())
    }
    result["selected"] = selected
    result["selected_count"] = len(selected)
    result["unused"] = unused
    result["shared"] = shared
    result["targets_detail"] = targets_detail
    result["stitched_single_proof_count"] = stitched
    result["verdict"] = PASS
    ctx.check(
        "shared-reduction",
        len(selected) < stitched,
        f"共同记录子集 {len(selected)} 条 < 各目标单条证明拼接 {stitched} 条"
        if len(selected) < stitched
        else f"共同记录子集 {len(selected)} 条；各目标单条证明拼接合计 {stitched} 条",
    )
    ctx.check(
        "tie-break",
        True,
        "记录数最少，且同规模下按 owner 哈希升序序列稳定裁决："
        + ",".join(best["seq"]),
    )
    return result
