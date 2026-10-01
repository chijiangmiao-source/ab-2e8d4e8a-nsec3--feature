"""审计判定集成测试：合法证明、环绕覆盖、各类拒绝场景。"""

import unittest

from app.nsec3 import nsec3_hash
from app.verifier import verify

ZONE = "example.cn"
SALT = "-"
ITER = 0


def build_chain(existing, zone=ZONE, salt=SALT, iter_=ITER, apex_types=None):
    """由名称集合生成一条按哈希排序的完整 NSEC3 环。"""
    ordered = sorted(existing, key=lambda n: int(nsec3_hash(n, salt, iter_), 32))
    hashes = [nsec3_hash(n, salt, iter_) for n in ordered]
    recs = []
    for i, (name, h) in enumerate(zip(ordered, hashes)):
        types = apex_types if (apex_types and name == zone) else (
            ["NS", "SOA", "RRSIG"] if name == zone else ["A", "RRSIG"]
        )
        recs.append({
            "owner_hash": h,
            "next_hash": hashes[(i + 1) % len(hashes)],
            "types": types,
        })
    return recs


DEFAULT_EXISTING = [
    "example.cn", "a.example.cn", "m.example.cn", "z.example.cn",
    "x.y.example.cn",
]


def payload(target, recs, audit_id="t", **kw):
    return {
        "audit_id": audit_id, "zone": ZONE, "target": target,
        "salt": SALT, "iterations": ITER, "records": recs, **kw,
    }


class ValidProofTests(unittest.TestCase):
    def setUp(self):
        self.recs = build_chain(DEFAULT_EXISTING)

    def test_single_label_nxdomain(self):
        r = verify(payload("q.example.cn", self.recs, "p1"))
        self.assertEqual(r["verdict"], "passed", r["errors"])
        self.assertEqual(r["closest_encloser"]["name"], "example.cn")
        self.assertEqual(r["next_closer"]["name"], "q.example.cn")
        self.assertEqual(r["wildcard"]["name"], "*.example.cn")

    def test_deep_ce_is_apex(self):
        r = verify(payload("deep.sub.example.cn", self.recs, "p2"))
        self.assertEqual(r["verdict"], "passed", r["errors"])
        self.assertEqual(r["closest_encloser"]["name"], "example.cn")
        self.assertEqual(r["next_closer"]["name"], "sub.example.cn")

    def test_ce_below_apex_and_wraparound_wildcard(self):
        r = verify(payload("p.x.y.example.cn", self.recs, "p3"))
        self.assertEqual(r["verdict"], "passed", r["errors"])
        self.assertEqual(r["closest_encloser"]["name"], "x.y.example.cn")
        self.assertEqual(r["next_closer"]["name"], "p.x.y.example.cn")
        self.assertEqual(r["wildcard"]["name"], "*.x.y.example.cn")
        wrap_recs = [x for x in r["records"]
                     if x["covers_wildcard"] and x["wrap_direction"] == "wrap"]
        self.assertTrue(wrap_recs, "通配符应被一条环绕区间覆盖")

    def test_hashes_recomputed_for_all_ancestors(self):
        r = verify(payload("p.x.y.example.cn", self.recs, "p4"))
        names = [a["name"] for a in r["ancestors"]]
        self.assertEqual(
            names,
            ["p.x.y.example.cn", "x.y.example.cn", "y.example.cn", "example.cn"],
        )
        for a in r["ancestors"]:
            self.assertEqual(a["hash"], nsec3_hash(a["name"], SALT, ITER))


class RejectTests(unittest.TestCase):
    def setUp(self):
        self.recs = build_chain(DEFAULT_EXISTING)

    def codes(self, r):
        return {e["code"] for e in r["errors"]}

    def test_missing_next_closer_coverage(self):
        r4 = next(x for x in self.recs
                  if x["owner_hash"] == nsec3_hash("z.example.cn", SALT, ITER))
        recs = [x for x in self.recs if x is not r4]
        r = verify(payload("q.example.cn", recs, "n1"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("NO_NEXT_CLOSER_COVERAGE", self.codes(r))

    def test_missing_wildcard_coverage(self):
        r3 = next(x for x in self.recs
                  if x["owner_hash"] == nsec3_hash("m.example.cn", SALT, ITER))
        recs = [x for x in self.recs if x is not r3]
        r = verify(payload("q.example.cn", recs, "n2"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("NO_WILDCARD_COVERAGE", self.codes(r))

    def test_wrong_salt(self):
        r = verify(payload("q.example.cn", self.recs, "n3", salt="aa"))
        self.assertEqual(r["verdict"], "rejected")

    def test_wrong_iterations(self):
        r = verify(payload("q.example.cn", self.recs, "n4", iterations=1))
        self.assertEqual(r["verdict"], "rejected")

    def test_target_exists(self):
        r = verify(payload("a.example.cn", self.recs, "n5"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("TARGET_EXISTS", self.codes(r))

    def test_invalid_base32(self):
        bad = [dict(self.recs[0], owner_hash="wxyz")] + self.recs[1:]
        r = verify(payload("q.example.cn", bad, "n6"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("BAD_OWNER_HASH", self.codes(r))

    def test_opt_out_rejected(self):
        bad = [dict(self.recs[0], opt_out=True)] + self.recs[1:]
        r = verify(payload("q.example.cn", bad, "n7"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("OPTOUT_UNSUPPORTED", self.codes(r))

    def test_duplicate_owner_rejected(self):
        bad = [dict(self.recs[0])] + self.recs
        r = verify(payload("q.example.cn", bad, "n8"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertTrue(
            {"DUPLICATE_OWNER", "CONFLICTING_ASSERTION"} & self.codes(r)
        )

    def test_conflicting_assertion_same_owner(self):
        bad = [dict(self.recs[0], next_hash=self.recs[0]["owner_hash"])] + self.recs[1:]
        r = verify(payload("q.example.cn", bad, "n9"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("DEGENERATE_INTERVAL", self.codes(r))

    def test_forged_interval_conflicts_with_owner(self):
        bad = [dict(x) for x in self.recs]
        # 把一条记录的 next 改为环中其他 owner，制造区间/owner 断言冲突
        bad[3]["next_hash"] = bad[0]["owner_hash"]
        r = verify(payload("q.example.cn", bad, "n10"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("ASSERTION_CONFLICT", self.codes(r))

    def test_empty_records(self):
        r = verify(payload("q.example.cn", [], "n11"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("NO_RECORDS", self.codes(r))

    def test_out_of_zone(self):
        r = verify(payload("x.other.net", self.recs, "n12", zone="example.cn"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("OUT_OF_ZONE", self.codes(r))

    def test_target_is_apex(self):
        r = verify(payload("example.cn", self.recs, "n13"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("TARGET_IS_APEX", self.codes(r))

    def test_duplicate_bitmap_type(self):
        bad = [dict(self.recs[0], types="A A RRSIG")] + self.recs[1:]
        r = verify(payload("q.example.cn", bad, "n14"))
        self.assertEqual(r["verdict"], "rejected")

    def test_bad_audit_id(self):
        r = verify(payload("q.example.cn", self.recs, "bad id"))
        self.assertEqual(r["verdict"], "rejected")
        self.assertIn("BAD_AUDIT_ID", self.codes(r))


class SaltedChainTests(unittest.TestCase):
    def test_salted_iterated_chain_passes_and_wraps(self):
        salt = "a5cba327531740b3"
        iters = 12
        existing = ["example.cn", "a.example.cn", "x.y.example.cn"]
        recs = build_chain(existing, salt=salt, iter_=iters)
        r = verify({
            "audit_id": "s1", "zone": "example.cn",
            "target": "p.x.y.example.cn", "salt": salt,
            "iterations": iters, "records": recs,
        })
        self.assertEqual(r["verdict"], "passed", r["errors"])
        self.assertEqual(r["closest_encloser"]["name"], "x.y.example.cn")


if __name__ == "__main__":
    unittest.main()
