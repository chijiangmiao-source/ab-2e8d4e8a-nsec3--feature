"""多目标共同记录证据包测试：

- 共享记录使总数少于各目标单条证明拼接；
- 增加一条记录即改变最近存在祖先、使候选子集失效（引擎逐目标重算）；
- 最优性：记录数最少 + owner 哈希序列字典序裁决（对 2^n 全子集暴力枚举对照）；
- 来源非通过/越区/重复目标/数量越界等拒绝面；
- 来源区域/盐值/迭代/完整记录组冻结进包，原审计绝不被改写；
- 证据包标识改换来源或目标冲突（409）与按包标识重开。
"""

import itertools
import json
import os
import random
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.nsec3 import nsec3_hash
from app.packages import build_package
from app.server import build_server
from app.storage import Store
from app.verifier import evaluate_target, parse_records, verify, _Ctx

ZONE = "example.cn"
SALT = "-"
ITER = 0

EXISTING = [
    "example.cn", "a.example.cn", "m.example.cn",
    "z.example.cn", "x.y.example.cn",
]


def build_chain(existing, zone=ZONE, salt=SALT, iter_=ITER):
    ordered = sorted(existing, key=lambda n: int(nsec3_hash(n, salt, iter_), 32))
    hashes = [nsec3_hash(n, salt, iter_) for n in ordered]
    return [{
        "owner_hash": h,
        "next_hash": hashes[(i + 1) % len(hashes)],
        "types": ["NS", "SOA", "RRSIG"] if ordered[i] == zone else ["A", "RRSIG"],
    } for i, h in enumerate(hashes)]


def source_audit(audit_id, target="q.example.cn", recs=None):
    recs = recs if recs is not None else build_chain(EXISTING)
    result = verify({
        "audit_id": audit_id, "zone": ZONE, "target": target,
        "salt": SALT, "iterations": ITER, "records": recs,
    })
    return {"fingerprint": "fp-" + audit_id, "result": result}, recs


def make_package(targets, source_id="SRC", package_id="PKG", source_record=None):
    if source_record is None:
        source_record, _ = source_audit(source_id)
    return build_package(
        {"package_id": package_id, "source_audit_id": source_id, "targets": targets},
        source_record,
    )


def codes(result):
    return {e["code"] for e in result["errors"]}


class ReductionTests(unittest.TestCase):
    def setUp(self):
        self.recs = build_chain(EXISTING)

    def test_shared_records_reduce_total(self):
        """验收点：共享记录减少总数（< 各目标单条证明拼接）。"""
        targets = ["q.example.cn", "p.x.y.example.cn"]
        res = make_package(targets, source_id="SRC-RED")
        self.assertEqual(res["verdict"], "passed", res["errors"])
        self.assertLess(
            res["selected_count"], res["stitched_single_proof_count"],
            f"共同子集 {res['selected_count']} 应少于拼接 "
            f"{res['stitched_single_proof_count']}",
        )
        self.assertEqual(res["stitched_single_proof_count"], 4)
        self.assertEqual(res["selected_count"], 3)
        self.assertTrue(res["shared"], "应存在被多目标共享的记录")
        # 每个目标都必须齐备 CE/NC/WC 三角色
        for d in res["targets_detail"]:
            roles = {tag for tags in d["roles"].values() for tag in tags}
            self.assertEqual(roles, {"ce", "nc", "wc"}, d["target"])
        # 未选用记录也要列出
        self.assertEqual(
            res["selected_count"] + len(res["unused"]), res["total_source_records"]
        )

    def test_each_target_recomputed_not_stitched(self):
        """结论中的角色必须来自共同子集上的逐目标重算。"""
        targets = ["q.example.cn", "p.x.y.example.cn"]
        res = make_package(targets, source_id="SRC-RC")
        selected_owners = {r["owner_hash"] for r in res["selected"]}
        for d in res["targets_detail"]:
            # 用选定子集独立复算该目标，须通过且 CE 一致
            sub = [r for r in self.recs if r["owner_hash"] in selected_owners]
            records = parse_records(sub, _Ctx())
            ev = evaluate_target(d["target"], ZONE, SALT, ITER, records)
            self.assertTrue(ev.passed, ev.errors)
            self.assertEqual(
                ev.closest_encloser["name"], d["closest_encloser"]["name"]
            )


class InvalidationTests(unittest.TestCase):
    """增加一条记录即改变最近存在祖先而使候选失效。"""

    def setUp(self):
        self.recs = build_chain(EXISTING)
        # 两个较深目标在最优解中使用浅层 CE（apex），仅需 2 条记录；
        # 一旦加入 x.y.example.cn 的 owner 记录，CE 下移到 x.y，
        # 新的下一层名称不再被覆盖，候选立即失效。
        self.targets = ["h.gh.x.y.example.cn", "gh.x.y.example.cn"]
        self.res = make_package(self.targets, source_id="SRC-INV")
        self.assertEqual(self.res["verdict"], "passed", self.res["errors"])

    def test_add_one_record_moves_ce_and_invalidates(self):
        self.assertEqual(self.res["selected_count"], 2)
        selected_owners = {r["owner_hash"] for r in self.res["selected"]}
        shallow = [r for r in self.recs if r["owner_hash"] in selected_owners]
        x_y_owner = nsec3_hash("x.y.example.cn", SALT, ITER)
        added = next(r for r in self.recs if r["owner_hash"] == x_y_owner)

        # 原候选子集上两个目标都通过，CE 均为 apex
        for t in self.targets:
            r = verify({
                "audit_id": "sub", "zone": ZONE, "target": t,
                "salt": SALT, "iterations": ITER, "records": shallow,
            })
            self.assertEqual(r["verdict"], "passed", r["errors"])
            self.assertEqual(r["closest_encloser"]["name"], ZONE)

        # 仅增加一条记录（x.y 的 owner）：CE 下移，下一层名称失去覆盖
        for t in self.targets:
            r = verify({
                "audit_id": "sub+1", "zone": ZONE, "target": t,
                "salt": SALT, "iterations": ITER,
                "records": shallow + [added],
            })
            self.assertEqual(r["verdict"], "rejected")
            self.assertEqual(r["closest_encloser"]["name"], "x.y.example.cn")
            self.assertIn("NO_NEXT_CLOSER_COVERAGE", codes(r))

    def test_engine_enumerates_per_target_and_picks_valid(self):
        """引擎枚举统计中复算候选数 ≥ 1，最终选择对所有目标成立。"""
        self.assertGreaterEqual(self.res["candidate_stats"]["evaluated"], 1)
        self.assertGreaterEqual(self.res["candidate_stats"]["feasible"], 1)


class OptimalityOracleTests(unittest.TestCase):
    """对全部 2^n 子集暴力枚举，引擎结果必须等于 (记录数, owner 序列) 最优。"""

    def setUp(self):
        self.recs = build_chain(EXISTING)
        self.all_records = parse_records(self.recs, _Ctx())
        self.pool = [
            "q.example.cn", "b.example.cn", "c.example.cn", "r.example.cn",
            "p.x.y.example.cn", "k.x.y.example.cn", "l.x.y.example.cn",
            "gh.x.y.example.cn", "h.gh.x.y.example.cn",
        ]
        # 只保留在完整记录组上可证明的目标
        self.provable = [
            t for t in self.pool
            if evaluate_target(t, ZONE, SALT, ITER, self.all_records).passed
        ]

    def _brute_best(self, targets):
        best = None
        for k in range(1, len(self.recs) + 1):
            for combo in itertools.combinations(range(len(self.recs)), k):
                sub = [self.all_records[i] for i in combo]
                if all(
                    evaluate_target(t, ZONE, SALT, ITER, sub).passed
                    for t in targets
                ):
                    seq = tuple(sorted(self.recs[i]["owner_hash"] for i in combo))
                    if best is None or (len(seq), seq) < (len(best), best):
                        best = seq
            if best is not None:
                return best
        return None

    def test_engine_matches_brute_force(self):
        rng = random.Random(20261001)
        checked = 0
        for size in (2, 3):
            for _ in range(40):
                targets = rng.sample(self.provable, size)
                res = make_package(targets, source_id=f"SRC-B{checked}",
                                   package_id=f"PKG-B{checked}")
                if res["verdict"] != "passed":
                    self.assertIsNone(self._brute_best(targets))
                    continue
                expected = self._brute_best(targets)
                got = tuple(sorted(r["owner_hash"] for r in res["selected"]))
                self.assertEqual(got, expected, f"targets={targets}")
                # 引擎结果不得劣于简单拼接
                self.assertLessEqual(
                    res["selected_count"], res["stitched_single_proof_count"]
                )
                checked += 1
        self.assertGreater(checked, 10)

    def test_deterministic_tie_break(self):
        """同输入多次构建，owner 哈希裁决序列完全一致。"""
        targets = ["q.example.cn", "b.example.cn", "p.x.y.example.cn"]
        r1 = make_package(targets, package_id="D1")
        r2 = make_package(targets, package_id="D2")
        s1 = [r["owner_hash"] for r in r1["selected"]]
        s2 = [r["owner_hash"] for r in r2["selected"]]
        self.assertEqual(s1, s2)
        self.assertEqual(s1, sorted(s1))  # 按 owner 哈希升序输出


class RejectionTests(unittest.TestCase):
    def setUp(self):
        self.recs = build_chain(EXISTING)
        self.good, _ = source_audit("GOOD")

    def test_source_not_found(self):
        res = build_package(
            {"package_id": "P", "source_audit_id": "NOPE",
             "targets": ["q.example.cn", "b.example.cn"]}, None)
        self.assertEqual(res["verdict"], "rejected")
        self.assertIn("SOURCE_NOT_FOUND", codes(res))

    def test_source_not_passed(self):
        bad = verify({
            "audit_id": "BAD", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER,
            "records": self.recs[:3],  # 截断 → rejected
        })
        self.assertEqual(bad["verdict"], "rejected")
        res = build_package(
            {"package_id": "P", "source_audit_id": "BAD",
             "targets": ["q.example.cn", "b.example.cn"]},
            {"fingerprint": "fp", "result": bad})
        self.assertEqual(res["verdict"], "rejected")
        self.assertIn("SOURCE_NOT_PASSED", codes(res))

    def test_out_of_zone(self):
        res = build_package(
            {"package_id": "P", "source_audit_id": "GOOD",
             "targets": ["q.example.cn", "host.other.net"]}, self.good)
        self.assertIn("OUT_OF_ZONE", codes(res))

    def test_duplicate_targets(self):
        res = build_package(
            {"package_id": "P", "source_audit_id": "GOOD",
             "targets": ["q.example.cn", "Q.Example.CN"]}, self.good)
        self.assertIn("DUP_TARGET", codes(res))

    def test_target_count_bounds(self):
        res = build_package(
            {"package_id": "P", "source_audit_id": "GOOD",
             "targets": ["q.example.cn"]}, self.good)
        self.assertIn("TOO_FEW_TARGETS", codes(res))
        res = build_package(
            {"package_id": "P", "source_audit_id": "GOOD",
             "targets": [f"t{i}.example.cn" for i in range(7)]}, self.good)
        self.assertIn("TOO_MANY_TARGETS", codes(res))

    def test_target_is_apex(self):
        res = build_package(
            {"package_id": "P", "source_audit_id": "GOOD",
             "targets": ["q.example.cn", ZONE]}, self.good)
        self.assertIn("TARGET_IS_APEX", codes(res))

    def test_existing_target_unprovable(self):
        res = build_package(
            {"package_id": "P", "source_audit_id": "GOOD",
             "targets": ["q.example.cn", "a.example.cn"]}, self.good)
        self.assertEqual(res["verdict"], "rejected")
        self.assertIn("TARGET_UNPROVABLE", codes(res))

    def test_bad_package_id(self):
        res = build_package(
            {"package_id": "bad id", "source_audit_id": "GOOD",
             "targets": ["q.example.cn", "b.example.cn"]}, self.good)
        self.assertIn("BAD_PACKAGE_ID", codes(res))

    def test_frozen_source_params(self):
        res = make_package(["q.example.cn", "b.example.cn"], source_id="GOOD")
        self.assertEqual(res["zone"], ZONE)
        self.assertEqual(res["salt"], SALT)
        self.assertEqual(res["iterations"], ITER)
        self.assertEqual(res["total_source_records"], len(self.recs))
        # 完整记录组被冻结进证据包
        self.assertEqual(
            [(r["owner_hash"], r["next_hash"]) for r in res["frozen_source_records"]],
            [(r["owner_hash"], r["next_hash"]) for r in self.recs],
        )


class StoragePackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(tempfile.mkdtemp(), "audits.json")
        self.store = Store(self.tmp)
        self.recs = build_chain(EXISTING)
        src = verify({
            "audit_id": "A1", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs,
        })
        self.store.submit(src)
        self.before = json.dumps(self.store.get("A1"), sort_keys=True)

    def test_freeze_reopen_tamper_and_no_rewrite(self):
        sr = self.store.get("A1")
        res = build_package(
            {"package_id": "PK1", "source_audit_id": "A1",
             "targets": ["q.example.cn", "p.x.y.example.cn"]}, sr)
        record, status = self.store.submit_package(res)
        self.assertEqual(status, "frozen")
        self.assertEqual(self.store.submit_package(res)[1], "unchanged")

        # 原审计字节级不变
        self.assertEqual(
            json.dumps(self.store.get("A1"), sort_keys=True), self.before
        )

        # 改换目标 → reuse 冲突，原包不变
        changed = build_package(
            {"package_id": "PK1", "source_audit_id": "A1",
             "targets": ["q.example.cn", "b.example.cn"]}, sr)
        conflict, status = self.store.submit_package(changed)
        self.assertEqual(status, "reuse")
        self.assertTrue(conflict["reuse"])
        frozen = self.store.get_package("PK1")["result"]
        self.assertEqual(frozen["targets"],
                         ["q.example.cn", "p.x.y.example.cn"])

        # 改换来源 → 同样冲突
        src2 = verify({
            "audit_id": "A2", "zone": ZONE, "target": "b.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs,
        })
        self.store.submit(src2)
        other_source = build_package(
            {"package_id": "PK1", "source_audit_id": "A2",
             "targets": ["q.example.cn", "p.x.y.example.cn"]},
            self.store.get("A2"))
        self.assertEqual(self.store.submit_package(other_source)[1], "reuse")

        # 按标识重开
        self.assertIsNotNone(self.store.get_package("PK1"))
        self.assertIsNone(self.store.get_package("NOPE"))
        self.assertIn("PK1", self.store.list_package_ids())


class PackageApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        os.environ["AUDIT_DB"] = os.path.join(cls.tmpdir, "pkg.json")
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.recs = build_chain(EXISTING)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, path, payload=None):
        if payload is None:
            req = urllib.request.Request(self.url(path))
        else:
            req = urllib.request.Request(
                self.url(path), data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_package_lifecycle(self):
        status, body = self.request("/api/audits", {
            "audit_id": "API-SRC", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs})
        self.assertEqual(status, 200)

        payload = {"package_id": "API-PKG", "source_audit_id": "API-SRC",
                   "targets": ["q.example.cn", "p.x.y.example.cn"]}
        status, body = self.request("/api/packages", payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["result"]["verdict"], "passed")
        self.assertLess(body["result"]["selected_count"],
                        body["result"]["stitched_single_proof_count"])
        self.assertEqual(body["status"], "frozen")

        status, body = self.request("/api/packages?id=API-PKG")
        self.assertEqual(status, 200)
        self.assertTrue(body["found"])
        self.assertEqual(body["result"]["source_audit_id"], "API-SRC")
        self.assertEqual(len(body["result"]["targets_detail"]), 2)

        status, body = self.request("/api/packages")
        self.assertIn("API-PKG", body["package_ids"])

        # 幂等
        status, body = self.request("/api/packages", payload)
        self.assertEqual(body["status"], "unchanged")

    def test_package_rejected_422(self):
        self.request("/api/audits", {
            "audit_id": "API-SRC2", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs})
        status, body = self.request("/api/packages", {
            "package_id": "API-PKG-BAD", "source_audit_id": "API-SRC2",
            "targets": ["q.example.cn", "a.example.cn"]})
        self.assertEqual(status, 422)
        self.assertEqual(body["result"]["verdict"], "rejected")

    def test_package_source_missing(self):
        status, body = self.request("/api/packages", {
            "package_id": "API-PKG-NS", "source_audit_id": "GHOST",
            "targets": ["q.example.cn", "b.example.cn"]})
        self.assertEqual(status, 422)
        self.assertIn("SOURCE_NOT_FOUND",
                      {e["code"] for e in body["result"]["errors"]})

    def test_package_tamper_conflict_409(self):
        self.request("/api/audits", {
            "audit_id": "API-SRC3", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs})
        p = {"package_id": "API-PKG-409", "source_audit_id": "API-SRC3",
             "targets": ["q.example.cn", "p.x.y.example.cn"]}
        self.request("/api/packages", p)
        status, body = self.request("/api/packages", {
            **p, "targets": ["q.example.cn", "b.example.cn"]})
        self.assertEqual(status, 409)
        self.assertTrue(body["reuse"])

    def test_unknown_package_404(self):
        status, body = self.request("/api/packages?id=MISSING")
        self.assertEqual(status, 404)
        self.assertFalse(body["found"])

    def test_single_target_audit_unchanged_after_package(self):
        """既有单目标审计读取与复核仍保持原结果。"""
        self.request("/api/audits", {
            "audit_id": "API-KEEP", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs})
        self.request("/api/packages", {
            "package_id": "API-KEEP-PKG", "source_audit_id": "API-KEEP",
            "targets": ["q.example.cn", "p.x.y.example.cn"]})
        status, body = self.request("/api/audits?id=API-KEEP")
        r = body["result"]
        self.assertEqual(r["verdict"], "passed")
        self.assertEqual(r["target"], "q.example.cn")
        self.assertEqual(r["closest_encloser"]["name"], ZONE)
        self.assertEqual(r["next_closer"]["name"], "q.example.cn")
        self.assertEqual(r["wildcard"]["name"], "*.example.cn")
        self.assertEqual(len(r["records"]), len(self.recs))


if __name__ == "__main__":
    unittest.main()
