"""NSEC3 NXDOMAIN 证明的核心审计逻辑（RFC 5155 §8.9）。

合法的“名称不存在”证明必须同时给出：
  1. 最近存在祖先 closest encloser（CE）：目标祖先链上最深的、其 NSEC3 owner
     哈希确实出现在记录组中的名称；
  2. 下一层名称（next closer name，NC）：CE 到目标路径上的第一层不存在名称，
     其哈希必须落在某条 NSEC3 记录的环形半开区间 (owner, next) 内；
  3. 通配符名 *.CE：其哈希同样必须被一条（无 Opt-Out 的）NSEC3 区间覆盖，
     以排除通配符展开。
三者缺一即证据不足，任何非法/冲突输入一律 rejected。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .nsec3 import (
    AuditError,
    ancestor_chain,
    b32hex_canonical,
    b32hex_decode,
    is_subdomain,
    normalise_domain,
    normalise_salt,
    nsec3_hash,
    parse_type_bitmap,
)
import re

PASS = "passed"
REJECT = "rejected"


@dataclass
class Record:
    ref: str
    owner_hash: str
    next_hash: str
    types: list[str]
    opt_out: bool = False
    wrap: bool = False
    covers_nc: bool = False
    covers_wc: bool = False
    raw_owner: str = ""
    raw_next: str = ""


@dataclass
class _Ctx:
    errors: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)

    def fail(self, code: str, msg: str) -> None:
        self.errors.append({"code": code, "message": msg})

    def check(self, name: str, ok: bool, detail: str) -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})


def _h2int(b32: str) -> int:
    return int.from_bytes(b32hex_decode(b32), "big")


def ring_interval(owner: int, nxt: int, h: int) -> tuple[bool, bool]:
    """返回 (h 是否落在半开环形区间, 是否环绕)。owner==next 为退化空区间。"""
    if owner == nxt:
        return False, False
    wrap = owner > nxt
    if wrap:
        return (h > owner or h < nxt), True
    return owner < h < nxt, False


def _parse_records(raw_records, ctx: _Ctx) -> list[Record]:
    if not isinstance(raw_records, list) or not raw_records:
        ctx.fail("NO_RECORDS", "记录组为空：证据不足")
        return []
    records: list[Record] = []
    seen: dict[str, Record] = {}
    for idx, item in enumerate(raw_records, 1):
        ref = f"R{idx}"
        if not isinstance(item, dict):
            ctx.fail("BAD_RECORD", f"{ref}: 记录格式不是对象")
            continue
        opt_out = bool(item.get("opt_out", False))
        if opt_out:
            ctx.fail("OPTOUT_UNSUPPORTED", f"{ref}: 服务仅处理无 Opt-Out 的 NSEC3")
        owner_raw = str(item.get("owner_hash", ""))
        next_raw = str(item.get("next_hash", ""))
        types_field = item.get("types", item.get("bitmap", ""))
        if isinstance(types_field, list):
            types = [str(t).upper() for t in types_field]
            if len(types) != len(set(types)):
                ctx.fail("DUP_TYPE", f"{ref}: 类型位图存在重复类型")
                types = sorted(set(types))
            for t in types:
                if not re.fullmatch(r"[A-Z][A-Z0-9]*", t):
                    ctx.fail("BAD_TYPE", f"{ref}: 非法类型 {t!r}")
        else:
            try:
                types = parse_type_bitmap(str(types_field))
            except AuditError as exc:
                ctx.fail("BAD_BITMAP", f"{ref}: {exc}")
                types = []
        try:
            owner = b32hex_canonical(owner_raw)
        except AuditError as exc:
            ctx.fail("BAD_OWNER_HASH", f"{ref}: owner 哈希 {exc}")
            owner = ""
        try:
            nxt = b32hex_canonical(next_raw)
        except AuditError as exc:
            ctx.fail("BAD_NEXT_HASH", f"{ref}: next 哈希 {exc}")
            nxt = ""
        if owner and nxt and owner == nxt:
            ctx.fail("DEGENERATE_INTERVAL", f"{ref}: owner 与 next 相同，退化空区间无法证明任何名称不存在")
        rec = Record(
            ref=ref,
            owner_hash=owner,
            next_hash=nxt,
            types=sorted(types),
            opt_out=opt_out,
            raw_owner=owner_raw,
            raw_next=next_raw,
        )
        if owner and owner in seen:
            prev = seen[owner]
            sig = (nxt, tuple(sorted(types)), opt_out)
            prev_sig = (prev.next_hash, tuple(prev.types), prev.opt_out)
            if sig == prev_sig:
                ctx.fail(
                    "DUPLICATE_OWNER",
                    f"{ref} 与 {prev.ref} owner 哈希完全重复：重复 owner 不得作为有效证据",
                )
            else:
                ctx.fail(
                    "CONFLICTING_ASSERTION",
                    f"{ref} 与 {prev.ref} owner 相同但 next/类型位图/Opt-Out 断言冲突",
                )
            continue
        if owner:
            seen[owner] = rec
        records.append(rec)
    return records


def verify(payload: dict) -> dict:
    """对一次提交执行审计，返回可冻结的完整结论字典。"""
    ctx = _Ctx()
    payload = payload or {}

    audit_id = str(payload.get("audit_id", "")).strip()
    if not audit_id or len(audit_id) > 128 or any(c.isspace() for c in audit_id):
        ctx.fail("BAD_AUDIT_ID", "审计标识须为非空且不含空白的字符串（≤128 字符）")

    try:
        zone = normalise_domain(str(payload.get("zone", "")))
    except AuditError as exc:
        zone = ""
        ctx.fail("BAD_ZONE", str(exc))

    try:
        target = normalise_domain(str(payload.get("target", "")))
    except AuditError as exc:
        target = ""
        ctx.fail("BAD_TARGET", str(exc))

    try:
        salt = normalise_salt(str(payload.get("salt", "-")))
    except AuditError as exc:
        salt = "-"
        ctx.fail("BAD_SALT", str(exc))

    raw_iter = payload.get("iterations", 0)
    if isinstance(raw_iter, bool) or isinstance(raw_iter, float):
        ctx.fail("BAD_ITERATIONS", "迭代次数须为 0..65535 的整数")
        iterations = 0
    else:
        try:
            iterations = int(raw_iter)
            if iterations < 0 or iterations > 65535:
                raise ValueError
        except (TypeError, ValueError):
            ctx.fail("BAD_ITERATIONS", "迭代次数须为 0..65535 的整数")
            iterations = 0

    if zone and target and not is_subdomain(target, zone):
        ctx.fail("OUT_OF_ZONE", f"目标 {target} 不在区域 {zone} 内")
    if zone and target == zone:
        ctx.fail("TARGET_IS_APEX", "目标即区域顶点，顶点名称必然存在，不可能为 NXDOMAIN")

    records = _parse_records(payload.get("records", []), ctx)

    result: dict = {
        "audit_id": audit_id,
        "zone": zone,
        "target": target,
        "salt": salt,
        "iterations": iterations,
        "algorithm": "SHA-1",
        "opt_out": False,
        "verdict": REJECT,
        "ancestors": [],
        "closest_encloser": None,
        "next_closer": None,
        "wildcard": None,
        "records": [],
        "checks": ctx.checks,
        "errors": ctx.errors,
        "frozen_at": None,
    }

    # 参数/记录本身有硬错误时，哈希复算已无意义，直接冻结拒绝结论。
    if not zone or not target or ctx.errors:
        result["records"] = [_record_public(r) for r in records]
        return result

    # 精确计算目标及各祖先的迭代哈希
    chain = ancestor_chain(target, zone)
    owner_map = {r.owner_hash: r for r in records if r.owner_hash}
    ancestors_view = []
    ce_name = None
    nc_name = None
    for name in chain:  # 从最深（目标自身）到最浅（zone）
        h = nsec3_hash(name, salt, iterations)
        exists = h in owner_map
        ancestors_view.append({"name": name, "hash": h, "owner_exists": exists})
        if exists and ce_name is None:
            ce_name = name  # 最深匹配者即最近存在祖先
    result["ancestors"] = ancestors_view

    if ce_name is None:
        ctx.fail(
            "NO_ENCLOSER",
            "记录组中找不到任何目标祖先的 owner 哈希：无法确定最近存在祖先，证据不足",
        )
    else:
        idx = chain.index(ce_name)
        nc_name = chain[idx - 1] if idx > 0 else None
        if ce_name == target:
            ctx.fail("TARGET_EXISTS", f"目标 {target} 的 owner 哈希存在，名称并未缺失")
        h_ce = nsec3_hash(ce_name, salt, iterations)
        h_wc_name = "*." + ce_name
        h_wc = nsec3_hash(h_wc_name, salt, iterations)
        result["closest_encloser"] = {
            "name": ce_name,
            "hash": h_ce,
            "record_ref": owner_map[h_ce].ref,
        }
        if h_wc in owner_map:
            ctx.fail(
                "WILDCARD_EXISTS",
                f"通配符 {h_wc_name} 的 owner 哈希存在，可能发生通配符展开，不能据此判定 NXDOMAIN",
            )
        result["wildcard"] = {"name": h_wc_name, "hash": h_wc}

        nc_info = None
        if nc_name is not None:
            h_nc = nsec3_hash(nc_name, salt, iterations)
            if h_nc in owner_map:
                ctx.fail(
                    "NEXT_CLOSER_EXISTS",
                    f"下一层名称 {nc_name} 的 owner 哈希存在，与“不存在”前提矛盾",
                )
            nc_info = {"name": nc_name, "hash": h_nc}
            result["next_closer"] = nc_info

        # 逐条判定环形半开区间归属与环绕方向
        nc_covers, wc_covers = [], []
        for r in records:
            if not r.owner_hash or not r.next_hash:
                continue
            o, n = _h2int(r.owner_hash), _h2int(r.next_hash)
            if nc_info is not None:
                inside, wrap = ring_interval(o, n, _h2int(nc_info["hash"]))
                r.covers_nc, r.wrap = inside, wrap
                if inside:
                    nc_covers.append(r.ref)
            if h_wc is not None:
                inside, wrap = ring_interval(o, n, _h2int(h_wc))
                if inside:
                    r.covers_wc = True
                    wc_covers.append(r.ref)
                # 同一 owner 的环绕方向唯一；nc 未覆盖时以 wc 计算结果补记
                if nc_info is None:
                    r.wrap = wrap

        ctx.check(
            "closest-encloser",
            True,
            f"最近存在祖先 {ce_name}（{h_ce}）由 {owner_map[h_ce].ref} 佐证",
        )
        if nc_info is not None:
            ok = bool(nc_covers)
            ctx.check(
                "next-closer-coverage",
                ok,
                f"下一层名称 {nc_info['name']}（{nc_info['hash']}）"
                + (f"落入 {','.join(nc_covers)} 的半开区间" if ok else "未被任何 NSEC3 区间覆盖（截断证据/证据不足）"),
            )
            if not ok:
                ctx.fail(
                    "NO_NEXT_CLOSER_COVERAGE",
                    f"下一层名称 {nc_info['name']}（{nc_info['hash']}）未落入任何记录的"
                    "半开哈希区间：证据被截断或区间错误，无法证明其不存在",
                )
        ok_wc = bool(wc_covers)
        ctx.check(
            "wildcard-coverage",
            ok_wc,
            f"通配符 {h_wc_name}（{h_wc}）"
            + (f"落入 {','.join(wc_covers)} 的半开区间，通配符展开已排除" if ok_wc else "缺少通配符不存在覆盖，无法排除通配符展开"),
        )
        if not ok_wc:
            ctx.fail(
                "NO_WILDCARD_COVERAGE",
                f"缺少覆盖通配符 {h_wc_name}（{h_wc}）的 NSEC3 区间："
                "无法排除通配符展开，不得判为 NXDOMAIN",
            )

    # 区间一致性：真实 NSEC3 链的半开区间互不重叠，任何其他记录的 owner
    # 都不应落入本记录区间（否则一条说它不存在、另一条说它存在：断言冲突）。
    valid = [r for r in records if r.owner_hash and r.next_hash]
    for r in valid:
        o, n = _h2int(r.owner_hash), _h2int(r.next_hash)
        for q in valid:
            if q.ref == r.ref:
                continue
            inside, _ = ring_interval(o, n, _h2int(q.owner_hash))
            if inside:
                ctx.fail(
                    "ASSERTION_CONFLICT",
                    f"{q.ref} 的 owner 哈希 {q.owner_hash} 落入 {r.ref} 的不存在区间，"
                    "区间与 owner 断言相互冲突",
                )

    # 浅祖先（含 zone 顶点）若也缺失，证据链同样不完整
    if zone:
        h_zone = nsec3_hash(zone, salt, iterations)
        zone_present = any(a["name"] == zone and a["owner_exists"] for a in ancestors_view)
        ctx.check(
            "apex-owner",
            zone_present,
            f"区域顶点 {zone}（{h_zone}）owner {'已出现' if zone_present else '缺失，证据不足'}",
        )
        if not zone_present:
            ctx.fail("NO_APEX_OWNER", f"记录组缺少区域顶点 {zone} 的 owner 证据")

    result["records"] = [_record_public(r) for r in records]
    result["verdict"] = PASS if not ctx.errors else REJECT
    return result


def _record_public(r: Record) -> dict:
    return {
        "ref": r.ref,
        "owner_hash": r.owner_hash,
        "next_hash": r.next_hash,
        "types": r.types,
        "opt_out": r.opt_out,
        "wrap_direction": "wrap" if r.wrap else "no-wrap",
        "covers_next_closer": r.covers_nc,
        "covers_wildcard": r.covers_wc,
    }


def payload_fingerprint(result: dict) -> str:
    """对审计载荷（不含结论/时间戳）计算指纹，用于检测标识复用与载荷篡改。"""
    import hashlib
    import json

    key_payload = {
        "zone": result["zone"],
        "target": result["target"],
        "salt": result["salt"],
        "iterations": result["iterations"],
        "algorithm": "SHA-1",
        "records": [
            [r["owner_hash"], r["next_hash"], r["types"], r["opt_out"]]
            for r in result.get("records", [])
        ],
    }
    return hashlib.sha256(
        json.dumps(key_payload, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
