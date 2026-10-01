"""多目标共享 NSEC3 证据包引擎（RFC 5155 §8.9 的多目标推广）。

值班员打开一份**已通过且已冻结**的单目标 NSEC3 审计后，可提交稳定证据包标识
与 2~6 个同区域规范目标名称。引擎从来源审计**冻结的完整记录组**中抽取一个
共同记录子集，使每个目标在该子集上重新复算后仍各自具备完整的三项证明角色：

  ① 最近存在祖先 CE（其 owner 记录须在子集中）
  ② 下一层名称 NC（哈希须被子集中某条记录的环形半开区间覆盖）
  ③ 通配符 *.CE（同样须被覆盖）

关键约束（见任务规约）：

* 来源审计的区域、盐值、迭代次数、完整记录组一律按冻结快照使用，绝不改写；
* CE/NC/通配符必须对**候选子集逐目标重新计算**——加入一条 owner 记录可能使
  CE 下移、被覆盖名称随之改变，从而让原本成立的子集失效，因此“把各目标各自
  的一条证明简单拼接”不保证可行，更不保证最优；
* 裁决顺序：先令子集记录数最少；记录数相同时按 owner 哈希序列（升序）做
  字典序稳定裁决；
* 冻结记录组本身即权威证据：若目标/某候选 NC/通配符的 owner 哈希出现在
  **完整冻结记录组**中，则不得靠“不选那条记录”虚构其不存在。
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from .nsec3 import (
    AuditError,
    ancestor_chain,
    is_subdomain,
    normalise_domain,
    nsec3_hash,
)
from .verifier import REJECT, PASS, ring_interval, _h2int

MIN_TARGETS = 2
MAX_TARGETS = 6


@dataclass
class _Option:
    """某个目标在“CE = chain[ce_index]”这一情形下对子集的全部要求。"""

    ce_index: int
    ce_ref: str
    forced: frozenset[int]          # 必须入选的记录（CE owner、顶点 owner）
    forbidden: frozenset[int]       # 一旦入选就会使 CE 下移/目标存在的记录
    cover_nc: frozenset[int]        # 可覆盖 NC 的记录
    cover_wc: frozenset[int]        # 可覆盖通配符的记录


@dataclass
class _TargetCtx:
    name: str
    chain: list[str]
    chain_hashes: list[str]
    options: list[_Option] = field(default_factory=list)


def _record_ints(records: list[dict]):
    owner_int = [_h2int(r["owner_hash"]) for r in records]
    next_int = [_h2int(r["next_hash"]) for r in records]
    return owner_int, next_int


def _cover_indices(owner_int, next_int, h: str) -> list[int]:
    hv = _h2int(h)
    return [
        i for i in range(len(owner_int))
        if ring_interval(owner_int[i], next_int[i], hv)[0]
    ]


def _normalise_targets(raw, zone: str, ctx_errors: list[dict]) -> list[str]:
    if not isinstance(raw, list):
        ctx_errors.append({"code": "BAD_TARGETS",
                           "message": "targets 必须是 2~6 个规范名称的数组"})
        return []
    targets: list[str] = []
    for item in raw:
        try:
            name = normalise_domain(str(item))
        except AuditError as exc:
            ctx_errors.append({"code": "BAD_TARGET",
                               "message": f"目标 {item!r} 非法：{exc}"})
            continue
        targets.append(name)
    if not any(e["code"] == "BAD_TARGET" for e in ctx_errors):
        if not (MIN_TARGETS <= len(targets) <= MAX_TARGETS):
            ctx_errors.append({
                "code": "BAD_TARGET_COUNT",
                "message": f"目标数量须为 {MIN_TARGETS}~{MAX_TARGETS} 个，实为 {len(targets)} 个",
            })
        if len(set(targets)) != len(targets):
            ctx_errors.append({"code": "DUP_TARGET",
                               "message": "目标名称重复：同一目标不得重复提交"})
        if zone:
            for name in targets:
                if not is_subdomain(name, zone):
                    ctx_errors.append({
                        "code": "OUT_OF_ZONE",
                        "message": f"目标 {name} 越区：不属于来源审计冻结区域 {zone}",
                    })
                if name == zone:
                    ctx_errors.append({
                        "code": "TARGET_IS_APEX",
                        "message": f"目标 {name} 即区域顶点，顶点必然存在",
                    })
    return targets


def _build_target_ctx(targets, source, records) -> tuple[list[_TargetCtx], list[dict]]:
    """在按 owner 哈希升序排列的 records 上枚举每个目标的全部可行 CE 情形。"""
    errors: list[dict] = []
    zone = source["zone"]
    salt = source["salt"]
    iterations = source["iterations"]
    owner_idx: dict[str, int] = {r["owner_hash"]: i for i, r in enumerate(records)}
    owner_int, next_int = _record_ints(records)
    apex_idx = owner_idx.get(nsec3_hash(zone, salt, iterations))

    ctxs: list[_TargetCtx] = []
    for name in targets:
        chain = ancestor_chain(name, zone)
        ch = [nsec3_hash(n, salt, iterations) for n in chain]
        tctx = _TargetCtx(name=name, chain=chain, chain_hashes=ch)

        # 目标自身的 owner 出现在**完整冻结记录组**中：名称按冻结证据即存在，
        # 不允许靠“抽掉那条记录”伪造不存在。
        if ch[0] in owner_idx:
            errors.append({
                "code": "TARGET_EXISTS",
                "message": f"目标 {name} 的 owner 哈希 {ch[0]} 存在于冻结完整记录组"
                           f"（{records[owner_idx[ch[0]]]['ref']}）：名称存在，不得证明 NXDOMAIN",
            })

        for i in range(1, len(chain)):
            if ch[i] not in owner_idx:
                continue  # 该祖先没有 owner 记录，无法作为 CE
            nc_hash = ch[i - 1]
            if nc_hash in owner_idx:
                # 冻结证据断言 NC 存在；选其 owner 只会让 CE 继续下移，
                # 停在这一层属于自相矛盾，该 CE 情形不可行。
                continue
            wc_name = "*." + chain[i]
            wc_hash = nsec3_hash(wc_name, salt, iterations)
            if wc_hash in owner_idx:
                continue  # 通配符实际存在，无法排除通配符展开
            cov_nc = _cover_indices(owner_int, next_int, nc_hash)
            cov_wc = _cover_indices(owner_int, next_int, wc_hash)
            if not cov_nc or not cov_wc:
                continue  # 冻结组中根本不存在所需覆盖
            forced = {owner_idx[ch[i]]}
            if apex_idx is not None:
                forced.add(apex_idx)
            forbidden = {owner_idx[ch[j]] for j in range(i) if ch[j] in owner_idx}
            tctx.options.append(_Option(
                ce_index=i,
                ce_ref=records[owner_idx[ch[i]]]["ref"],
                forced=frozenset(forced),
                forbidden=frozenset(forbidden),
                cover_nc=frozenset(cov_nc),
                cover_wc=frozenset(cov_wc),
            ))
        if not tctx.options:
            errors.append({
                "code": "NO_VIABLE_PROOF",
                "message": f"在冻结记录组上，目标 {name} 不存在任何可行的 CE/NC/通配符组合",
            })
        ctxs.append(tctx)
    return ctxs, errors


def _satisfied(tctx: _TargetCtx, sel: frozenset[int]) -> bool:
    for opt in tctx.options:
        if opt.forbidden & sel:
            continue
        if not opt.forced.issubset(sel):
            continue
        if not (opt.cover_nc & sel) or not (opt.cover_wc & sel):
            continue
        return True
    return False


def _prunable(tctx: _TargetCtx, sel: frozenset[int], reachable: frozenset[int]) -> bool:
    """已选 sel、其余只能从 reachable 增补时，该目标是否已彻底无解。"""
    pool = sel | reachable
    for opt in tctx.options:
        if opt.forbidden & sel:
            continue
        if not opt.forced.issubset(pool):
            continue
        if not (opt.cover_nc & pool) or not (opt.cover_wc & pool):
            continue
        return False
    return True


def _optimise(ctxs: list[_TargetCtx], n: int) -> list[int] | None:
    """迭代加深搜索：最少记录数 → owner 哈希升序序列字典序最小。

    记录已按 owner 哈希升序编号，做“先选入、后跳过”的深度优先枚举，
    同一最小规模下第一个命中的子集即 owner 哈希序列字典序最小者。
    """

    def dfs(pos: int, chosen: list[int], k: int) -> list[int] | None:
        if len(chosen) > k or len(chosen) + (n - pos) < k:
            return None
        sel = frozenset(chosen)
        reachable = frozenset(range(pos, n))
        for tctx in ctxs:
            if _prunable(tctx, sel, reachable):
                return None
        if pos == n:
            if len(chosen) == k and all(_satisfied(t, sel) for t in ctxs):
                return list(chosen)
            return None
        hit = dfs(pos + 1, chosen + [pos], k)   # 先选入：保证字典序最小
        if hit is not None:
            return hit
        return dfs(pos + 1, chosen, k)

    for k in range(1, n + 1):
        hit = dfs(0, [], k)
        if hit is not None:
            return hit
    return None


def _record_view(rec: dict) -> dict:
    o, n = _h2int(rec["owner_hash"]), _h2int(rec["next_hash"])
    return {
        "ref": rec["ref"],
        "owner_hash": rec["owner_hash"],
        "next_hash": rec["next_hash"],
        "types": list(rec["types"]),
        "opt_out": rec.get("opt_out", False),
        "wrap_direction": "wrap" if o > n else "no-wrap",
    }


def build_package(package_id: str, targets_raw, source: dict) -> dict:
    """依据来源审计冻结快照构建多目标共享证据包结论（可冻结）。

    source 必须是 verifier.verify() 产出并已冻结的完整结论字典，
    可附带 _fingerprint / _frozen_at 供证据包记录来源指纹与冻结时间。
    """
    errors: list[dict] = []
    pid = (package_id or "").strip()
    if not pid or len(pid) > 128 or any(c.isspace() for c in pid):
        errors.append({"code": "BAD_PACKAGE_ID",
                       "message": "证据包标识须为非空且不含空白的字符串（≤128 字符）"})

    if not isinstance(source, dict) or source.get("verdict") != PASS:
        # 调用方通常已先行拦截，这里兜底保证绝不基于非通过来源出证
        errors.append({
            "code": "SOURCE_NOT_PASSED",
            "message": "来源审计不存在或结论非通过：仅能从已通过的冻结审计抽取证据包",
        })

    zone = source.get("zone", "") if isinstance(source, dict) else ""
    targets = _normalise_targets(targets_raw, zone, errors)

    valid_records: list[dict] = []
    if isinstance(source, dict):
        for r in source.get("records", []):
            if r.get("owner_hash") and r.get("next_hash"):
                valid_records.append(r)

    doc: dict = {
        "package_id": pid,
        "kind": "nsec3-evidence-package",
        "source_audit_id": source.get("audit_id") if isinstance(source, dict) else None,
        "source_fingerprint": source.get("_fingerprint") if isinstance(source, dict) else None,
        "source_frozen_at": source.get("_frozen_at") if isinstance(source, dict) else None,
        "zone": zone,
        "salt": source.get("salt", "-") if isinstance(source, dict) else "-",
        "iterations": source.get("iterations", 0) if isinstance(source, dict) else 0,
        "algorithm": "SHA-1",
        "targets": targets,
        "verdict": REJECT,
        "selected_records": [],
        "unselected_records": [],
        "target_evidence": [],
        "record_attribution": [],
        "errors": errors,
        "frozen_at": None,
        # 冻结快照：来源区域/盐值/迭代次数已固定在上方，完整记录组原样封存
        "frozen_source_records": copy.deepcopy(valid_records),
    }

    if errors:
        return doc

    # owner 哈希升序排列（等长小写 base32hex 的字典序即 160 位数值序）
    records = sorted(valid_records, key=lambda r: r["owner_hash"])

    ctxs, hard_errors = _build_target_ctx(targets, source, records)
    errors.extend(hard_errors)

    chosen: list[int] | None = None
    if not hard_errors:
        chosen = _optimise(ctxs, len(records))
        if chosen is None:
            errors.append({
                "code": "NO_COMMON_SUBSET",
                "message": "无法从冻结完整记录组中抽出使所有目标同时通过的共同记录子集"
                           "（逐目标重算 CE/NC/通配符后无交集可行解）",
            })

    if errors:
        return doc

    chosen_set = set(chosen)
    doc["selected_records"] = [_record_view(records[i]) for i in chosen]
    doc["unselected_records"] = [
        {"ref": records[i]["ref"], "owner_hash": records[i]["owner_hash"],
         "next_hash": records[i]["next_hash"], "types": list(records[i]["types"])}
        for i in range(len(records)) if i not in chosen_set
    ]

    owner_int, next_int = _record_ints(records)
    sel_owner = {records[i]["owner_hash"] for i in chosen}
    by_ref = {v["ref"]: v for v in doc["selected_records"]}

    target_evidence = []
    attribution: dict[str, dict] = {}
    for tctx in ctxs:
        # 在选定子集上重新计算 CE：祖先链上最深的、owner 入选者
        ce_pos = next(
            j for j in range(len(tctx.chain_hashes) - 1, 0, -1)
            if tctx.chain_hashes[j] in sel_owner
        )
        ce_name = tctx.chain[ce_pos]
        ce_hash = tctx.chain_hashes[ce_pos]
        nc_name = tctx.chain[ce_pos - 1]
        nc_hash = tctx.chain_hashes[ce_pos - 1]
        wc_name = "*." + ce_name
        wc_hash = nsec3_hash(wc_name, doc["salt"], doc["iterations"])

        def first_cover(h: str) -> int:
            return next(
                i for i in chosen
                if ring_interval(owner_int[i], next_int[i], _h2int(h))[0]
            )

        ce_i = next(i for i in chosen if records[i]["owner_hash"] == ce_hash)
        nc_i = first_cover(nc_hash)
        wc_i = first_cover(wc_hash)
        ce_ref, nc_ref, wc_ref = (records[ce_i]["ref"],
                                  records[nc_i]["ref"], records[wc_i]["ref"])
        target_evidence.append({
            "target": tctx.name,
            "verdict": PASS,
            "closest_encloser": {"name": ce_name, "hash": ce_hash, "record_ref": ce_ref},
            "next_closer": {"name": nc_name, "hash": nc_hash, "covered_by": nc_ref,
                            "wrap_direction": by_ref[nc_ref]["wrap_direction"]},
            "wildcard": {"name": wc_name, "hash": wc_hash, "covered_by": wc_ref,
                         "wrap_direction": by_ref[wc_ref]["wrap_direction"]},
            "used_refs": sorted({ce_ref, nc_ref, wc_ref}, key=lambda x: int(x[1:])),
            "ancestors": [
                {"name": n, "hash": h,
                 "owner_exists_in_subset": h in sel_owner,
                 "owner_record_ref": (
                     next((records[i]["ref"] for i in chosen
                           if records[i]["owner_hash"] == h), None))}
                for n, h in zip(tctx.chain, tctx.chain_hashes)
            ],
        })
        for ref, role in ((ce_ref, "ce-owner"), (nc_ref, "covers-nc"),
                          (wc_ref, "covers-wildcard")):
            attribution.setdefault(ref, {"ref": ref, "roles": {}})["roles"] \
                .setdefault(tctx.name, []).append(role)

    doc["target_evidence"] = target_evidence
    # 顶点 owner 因证据完整性被每个可行选项强制选入；某些子集中它可能不直接
    # 承担 CE/覆盖角色，因此为全部入选记录兜底建立归属项。
    for v in doc["selected_records"]:
        attribution.setdefault(v["ref"], {"ref": v["ref"], "roles": {}})
    doc["record_attribution"] = [
        {**attribution[v["ref"]],
         "shared_by": len(attribution[v["ref"]]["roles"])}
        for v in doc["selected_records"]
    ]
    doc["verdict"] = PASS
    return doc


def package_fingerprint(doc: dict) -> str:
    """对证据包关键输入（来源及来源指纹、排序后目标集）计算指纹。

    证据包标识复用但改换来源或目标即指纹不符 → 409 拒绝，不覆盖原结论。
    """
    import hashlib
    import json

    key = {
        "source_audit_id": doc["source_audit_id"],
        "source_fingerprint": doc.get("source_fingerprint"),
        "targets": sorted(doc.get("targets", [])),
    }
    return hashlib.sha256(
        json.dumps(key, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
