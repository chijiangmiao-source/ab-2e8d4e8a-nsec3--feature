"""多目标共享证据包引擎测试。

覆盖：
* 共享记录使共同子集记录数少于各目标单证明的并集（朴素拼接）；
* 增加一条记录使最近存在祖先下移、候选子集失效，引擎仍须逐目标重算后取最优；
* 同规模下按 owner 哈希升序序列稳定裁决；
* 来源非通过、越区、重复目标、目标数越界、目标存在、无共同子集等拒绝面；
* 冻结快照不被改写；证据包指纹随来源/目标改换而改变。
"""

import unittest

from app.nsec3 import nsec3_hash
from app.verifier import verify
from app.evidence import build_package, package_fingerprint

ZONE = "example.cn"
SALT = "-"
ITER = 0

EXISTING = [
    "example.cn", "a.example.cn", "m.example.cn",
    "z.example.cn", "x.y.example.cn",
]

# 验收固定场景的两个目标
T_DEEP = "p.x.y.example.cn"    # 与 CE=apex 的 NC/通配符覆盖记录在 R5/R3
T_XY = "g.x.y.example.cn"      # 单独最优需要 x.y 的 owner 记录 R1
R_XY = "x.y.example.cn"


def H(name):
    return nsec3_hash(name, SALT, ITER)


def build_chain(existing):
    ordered = sorted(existing, key=lambda n: int(H(n), 32))
    hashes = [H(n) for n in ordered]
    return [{
        "owner_hash": h,
        "next_hash": hashes[(i + 1) % len(hashes)],
        "types": ["NS", "SOA", "RRSIG"] if ordered[i] == ZONE else ["A", "RRSIG"],
    } for i, h in enumerate(hashes)]


class PackageEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recs = build_chain(EXISTING)
        cls.source = verify({
            "audit_id": "SRC", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": cls.recs,
        })
        assert cls.source["verdict"] == "passed", cls.source["errors"]
        cls.source["_fingerprint"] = "fp-src"
        cls.source["_frozen_at"] = "2026-10-01T00:00:00Z"

    def codes(self, doc):
        return {e["code"] for e in doc["errors"]}

    def _ref_to_index(self, ref):
        return int(ref[1:]) - 1

    def test_shared_subset_smaller_than_stitched_union(self):
        """共同子集 2 条 < 两目标各自最优证明的并集 3 条。"""
        doc = build_package("PKG", [T_DEEP, T_XY], self.source)
        self.assertEqual(doc["verdict"], "passed", doc["errors"])
        selected = [r["ref"] for r in doc["selected_records"]]
        self.assertEqual(len(selected), 2, selected)

        # 各目标在各自最优子集上分别通过
        def per_target_refs(target):
            best = None
            import itertools
            for k in range(1, len(self.recs) + 1):
                for comb in itertools.combinations(range(len(self.recs)), k):
                    sub = [self.recs[i] for i in comb]
                    r = verify({"audit_id": "x", "zone": ZONE, "target": target,
                                "salt": SALT, "iterations": ITER, "records": sub})
                    if r["verdict"] == "passed":
                        return {f"R{i+1}" for i in comb}
            return set()

        union = per_target_refs(T_DEEP) | per_target_refs(T_XY)
        self.assertLess(len(selected), len(union),
                        f"共同子集 {selected} 应严格少于朴素拼接并集 {union}")

    def test_adding_owner_record_shifts_ce_and_invalidates(self):
        """在最优子集上多加 x.y 的 owner 记录：p.x.y 的 CE 下移且 NC 失去覆盖。"""
        doc = build_package("PKG", [T_DEEP, T_XY], self.source)
        self.assertEqual(doc["verdict"], "passed")
        # ref R{n} 对应来源记录组输入顺序的第 n 条
        sub_recs = [self.recs[int(ref[1:]) - 1]
                    for ref in (r["ref"] for r in doc["selected_records"])]

        xy_rec = next(r for r in self.recs if r["owner_hash"] == H(R_XY))
        before = verify({"audit_id": "x", "zone": ZONE, "target": T_DEEP,
                         "salt": SALT, "iterations": ITER, "records": sub_recs})
        after = verify({"audit_id": "x", "zone": ZONE, "target": T_DEEP,
                        "salt": SALT, "iterations": ITER,
                        "records": sub_recs + [xy_rec]})
        self.assertEqual(before["verdict"], "passed")
        self.assertEqual(before["closest_encloser"]["name"], ZONE)
        self.assertEqual(after["verdict"], "rejected")
        self.assertEqual(after["closest_encloser"]["name"], R_XY)
        self.assertIn("NO_NEXT_CLOSER_COVERAGE",
                      {e["code"] for e in after["errors"]})

        # 朴素拼接（并集含 x.y owner）因此不可能成立，引擎必须靠逐目标
        # 重算识别这一点，而不是直接拼接各自证明
        r = verify({"audit_id": "x", "zone": ZONE, "target": T_DEEP,
                    "salt": SALT, "iterations": ITER,
                    "records": sub_recs + [xy_rec]})
        self.assertEqual(r["verdict"], "rejected")

    def test_three_roles_per_target_and_attribution(self):
        doc = build_package("PKG", [T_DEEP, T_XY], self.source)
        self.assertEqual(doc["verdict"], "passed")
        targets_seen = []
        for te in doc["target_evidence"]:
            targets_seen.append(te["target"])
            self.assertEqual(te["verdict"], "passed")
            self.assertIsNotNone(te["closest_encloser"]["record_ref"])
            self.assertIsNotNone(te["next_closer"]["covered_by"])
            self.assertIsNotNone(te["wildcard"]["covered_by"])
            self.assertEqual(te["closest_encloser"]["name"], ZONE)
            # 三项角色齐备且 used_refs 非空
            self.assertTrue(te["used_refs"])
        self.assertEqual(sorted(targets_seen), sorted([T_DEEP, T_XY]))
        # 共享归属：入选记录都标记了两个目标
        for att in doc["record_attribution"]:
            self.assertEqual(att["shared_by"], 2, att)
        # 未选用记录列表完整
        self.assertEqual(
            len(doc["selected_records"]) + len(doc["unselected_records"]),
            len(self.recs),
        )

    def test_minimality_and_owner_hash_tiebreak(self):
        """再多加一个不增加所需覆盖的目标，结果仍取最少记录；
        同规模候选中 owner 哈希序列字典序最小者胜出。"""
        doc = build_package("PKG", [T_DEEP, T_XY, "k.example.cn"], self.source)
        self.assertEqual(doc["verdict"], "passed", doc["errors"])
        selected = [r["owner_hash"] for r in doc["selected_records"]]
        self.assertEqual(selected, sorted(selected))
        self.assertEqual(len(selected), 2)

    def test_recomputation_each_target_with_subset(self):
        """用子集记录直接跑单目标 verify，必须与证据包三角色结论一致。"""
        doc = build_package("PKG", [T_DEEP, T_XY], self.source)
        sub = [{
            "owner_hash": r["owner_hash"], "next_hash": r["next_hash"],
            "types": r["types"],
        } for r in doc["selected_records"]]
        for te in doc["target_evidence"]:
            r = verify({"audit_id": "x", "zone": ZONE, "target": te["target"],
                        "salt": SALT, "iterations": ITER, "records": sub})
            self.assertEqual(r["verdict"], "passed", (te["target"], r["errors"]))
            self.assertEqual(r["closest_encloser"]["name"],
                             te["closest_encloser"]["name"])
            self.assertEqual(r["next_closer"]["name"], te["next_closer"]["name"])

    # ── 拒绝面 ──────────────────────────────────────────────
    def test_source_must_be_passed(self):
        rejected = verify({
            "audit_id": "BAD", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": [],
        })
        self.assertEqual(rejected["verdict"], "rejected")
        doc = build_package("PKG", [T_DEEP, T_XY], rejected)
        self.assertEqual(doc["verdict"], "rejected")
        self.assertIn("SOURCE_NOT_PASSED", self.codes(doc))

    def test_out_of_zone_target_rejected(self):
        doc = build_package("PKG", [T_DEEP, "x.other.net"], self.source)
        self.assertEqual(doc["verdict"], "rejected")
        self.assertIn("OUT_OF_ZONE", self.codes(doc))

    def test_duplicate_targets_rejected(self):
        doc = build_package("PKG", [T_DEEP, T_DEEP], self.source)
        self.assertEqual(doc["verdict"], "rejected")
        self.assertIn("DUP_TARGET", self.codes(doc))

    def test_target_count_bounds(self):
        doc = build_package("PKG", ["q.example.cn"], self.source)
        self.assertIn("BAD_TARGET_COUNT", self.codes(doc))
        doc = build_package("PKG", [f"q{i}.example.cn" for i in range(7)],
                            self.source)
        self.assertIn("BAD_TARGET_COUNT", self.codes(doc))

    def test_existing_target_rejected(self):
        doc = build_package("PKG", ["a.example.cn", T_DEEP], self.source)
        self.assertEqual(doc["verdict"], "rejected")
        self.assertIn("TARGET_EXISTS", self.codes(doc))

    def test_no_common_subset_when_coverage_incompatible(self):
        """两个目标所需记录互斥时明确拒绝，不得拼接宣称通过。"""
        # 截断记录组：去掉 m 的 owner 记录后，q.example.cn 缺通配符覆盖，
        # 无法与同组其他目标组成共同子集
        truncated = [r for r in self.recs
                     if r["owner_hash"] != H("m.example.cn")]
        tr_source = verify({"audit_id": "TR", "zone": ZONE, "target": T_XY,
                            "salt": SALT, "iterations": ITER,
                            "records": truncated})
        self.assertEqual(tr_source["verdict"], "passed", tr_source["errors"])
        doc = build_package("PKG", ["q.example.cn", T_XY], tr_source)
        self.assertEqual(doc["verdict"], "rejected")
        self.assertTrue({"NO_VIABLE_PROOF", "NO_COMMON_SUBSET"} & self.codes(doc))

    def test_bad_package_id(self):
        for bad in ("", "has space", "x" * 129):
            doc = build_package(bad, [T_DEEP, T_XY], self.source)
            self.assertEqual(doc["verdict"], "rejected")
            self.assertIn("BAD_PACKAGE_ID", self.codes(doc))

    def test_source_snapshot_frozen_and_not_mutated(self):
        before = len(self.source["records"])
        doc = build_package("PKG", [T_DEEP, T_XY], self.source)
        self.assertEqual(doc["verdict"], "passed")
        self.assertEqual(doc["zone"], self.source["zone"])
        self.assertEqual(doc["salt"], self.source["salt"])
        self.assertEqual(doc["iterations"], self.source["iterations"])
        self.assertEqual(len(doc["frozen_source_records"]), before)
        # 原审计结论内容不被改写
        self.assertEqual(self.source["verdict"], "passed")
        self.assertEqual(len(self.source["records"]), before)
        self.assertEqual(self.source["target"], "q.example.cn")

    def test_fingerprint_changes_with_targets_or_source(self):
        d1 = build_package("PKG", [T_DEEP, T_XY], self.source)
        d2 = build_package("PKG", [T_DEEP, "k.example.cn"], self.source)
        self.assertNotEqual(package_fingerprint(d1),
                            package_fingerprint(d2))
        other = dict(self.source)
        other["_fingerprint"] = "fp-other"
        d3 = build_package("PKG", [T_DEEP, T_XY], other)
        self.assertNotEqual(package_fingerprint(d1),
                            package_fingerprint(d3))
        # 目标顺序不同不改变指纹（集合语义）
        d4 = build_package("PKG", [T_XY, T_DEEP], self.source)
        self.assertEqual(package_fingerprint(d1), package_fingerprint(d4))


class OptimiserTieBreakTests(unittest.TestCase):
    def test_minimum_size_then_owner_hash_sequence(self):
        from app.evidence import _Option, _TargetCtx, _optimise

        # 记录位置 0..4 已按 owner 哈希升序编号。
        # 目标 t1：必须含 0（CE），NC 与通配符可由 1 或 2 覆盖 →
        # 可行最小子集 {0,1} 与 {0,2}，按 owner 哈希序列应取 {0,1}。
        t1 = _TargetCtx(name="t1", chain=["t1", "z"], chain_hashes=["ht", "h0"], options=[
            _Option(ce_index=1, ce_ref="R1", forced=frozenset({0}),
                    forbidden=frozenset(),
                    cover_nc=frozenset({1, 2}), cover_wc=frozenset({1, 2})),
        ])
        # 目标 t2：必须含 0；记录 3 单独即可，但 {0,3} 规模相同且哈希序列更大，
        # 仅当更优解已被排除时才应选到它。
        t2 = _TargetCtx(name="t2", chain=["t2", "z"], chain_hashes=["ht2", "h0"], options=[
            _Option(ce_index=1, ce_ref="R1", forced=frozenset({0}),
                    forbidden=frozenset(),
                    cover_nc=frozenset({1, 3}), cover_wc=frozenset({1, 3})),
        ])
        self.assertEqual(_optimise([t1, t2], 5), [0, 1])

    def test_forbidden_owner_shifts_to_larger_subset(self):
        from app.evidence import _Option, _TargetCtx, _optimise

        # 选入记录 1 会使 CE 下移（forbidden），因此只能走 {0,2}。
        t = _TargetCtx(name="t", chain=["t", "z"], chain_hashes=["ht", "h0"], options=[
            _Option(ce_index=1, ce_ref="R1", forced=frozenset({0}),
                    forbidden=frozenset({1}),
                    cover_nc=frozenset({1, 2}), cover_wc=frozenset({1, 2})),
        ])
        self.assertEqual(_optimise([t], 3), [0, 2])


class SaltedPackageTests(unittest.TestCase):
    def test_salted_iterated_source(self):
        salt = "a5cba327531740b3"
        iters = 12
        existing = ["example.cn", "a.example.cn", "x.y.example.cn"]
        ordered = sorted(existing, key=lambda n: int(nsec3_hash(n, salt, iters), 32))
        hashes = [nsec3_hash(n, salt, iters) for n in ordered]
        recs = [{
            "owner_hash": h,
            "next_hash": hashes[(i + 1) % len(hashes)],
            "types": ["NS", "SOA", "RRSIG"] if ordered[i] == ZONE else ["A", "RRSIG"],
        } for i, h in enumerate(hashes)]
        source = verify({"audit_id": "S2", "zone": ZONE,
                         "target": "p.x.y.example.cn", "salt": salt,
                         "iterations": iters, "records": recs})
        self.assertEqual(source["verdict"], "passed")
        doc = build_package("PKG-S",
                            ["p.x.y.example.cn", "q.x.y.example.cn"], source)
        self.assertEqual(doc["verdict"], "passed", doc["errors"])
        self.assertEqual(doc["salt"], salt)
        self.assertEqual(doc["iterations"], iters)


if __name__ == "__main__":
    unittest.main()
