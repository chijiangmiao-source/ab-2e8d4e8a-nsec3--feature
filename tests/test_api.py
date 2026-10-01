"""HTTP/JSON API 冒烟测试：健康地址、页面、提交、重开、复用冲突。"""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.nsec3 import nsec3_hash
from app.server import build_server

ZONE = "example.cn"
SALT = "-"
ITER = 0


def build_chain(existing):
    ordered = sorted(existing, key=lambda n: int(nsec3_hash(n, SALT, ITER), 32))
    hashes = [nsec3_hash(n, SALT, ITER) for n in ordered]
    return [{
        "owner_hash": h,
        "next_hash": hashes[(i + 1) % len(hashes)],
        "types": ["NS", "SOA", "RRSIG"] if ordered[i] == ZONE else ["A", "RRSIG"],
    } for i, h in enumerate(hashes)]


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        os.environ["AUDIT_DB"] = os.path.join(cls.tmpdir, "audits.json")
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.recs = build_chain(
            ["example.cn", "a.example.cn", "m.example.cn",
             "z.example.cn", "x.y.example.cn"]
        )

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, path, payload=None):
        if payload is None:
            req = urllib.request.Request(self.url(path))
        else:
            req = urllib.request.Request(
                self.url(path),
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_health(self):
        status, body = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_page(self):
        with urllib.request.urlopen(self.url("/"), timeout=5) as resp:
            html = resp.read().decode()
        self.assertEqual(resp.status, 200)
        self.assertIn("NSEC3", html)
        self.assertIn("最近存在祖先", html)

    def test_submit_pass_and_reopen(self):
        payload = {
            "audit_id": "API-001", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs,
        }
        status, body = self.request("/api/audits", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["verdict"], "passed")
        self.assertEqual(body["status"], "frozen")

        status, body = self.request("/api/audits?id=API-001")
        self.assertEqual(status, 200)
        self.assertTrue(body["found"])
        self.assertEqual(body["result"]["closest_encloser"]["name"], ZONE)
        self.assertIsNotNone(body["frozen_at"])

    def test_second_identical_is_unchanged(self):
        payload = {
            "audit_id": "API-002", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs,
        }
        self.request("/api/audits", payload)
        status, body = self.request("/api/audits", payload)
        self.assertEqual(body["status"], "unchanged")

    def test_missing_wildcard_coverage_rejected(self):
        r3 = next(x for x in self.recs
                  if x["owner_hash"] == nsec3_hash("m.example.cn", SALT, ITER))
        recs = [x for x in self.recs if x is not r3]
        payload = {
            "audit_id": "API-003", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": recs,
        }
        status, body = self.request("/api/audits", payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["result"]["verdict"], "rejected")
        codes = {e["code"] for e in body["result"]["errors"]}
        self.assertIn("NO_WILDCARD_COVERAGE", codes)

    def test_illegal_record_rejected(self):
        bad = [dict(self.recs[0], owner_hash="wxyz!!")] + self.recs[1:]
        payload = {
            "audit_id": "API-004", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": bad,
        }
        status, body = self.request("/api/audits", payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["result"]["verdict"], "rejected")

    def test_audit_id_reuse_payload_change_conflict(self):
        p1 = {
            "audit_id": "API-005", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": self.recs,
        }
        self.request("/api/audits", p1)
        p2 = dict(p1, target="other.example.cn")
        status, body = self.request("/api/audits", p2)
        self.assertEqual(status, 409)
        self.assertTrue(body["reuse"])
        # 原结论保持不变
        _, body1 = self.request("/api/audits?id=API-005")
        self.assertEqual(body1["result"]["target"], "q.example.cn")

    def test_unknown_id_404(self):
        status, body = self.request("/api/audits?id=NOPE")
        self.assertEqual(status, 404)
        self.assertFalse(body["found"])

    def test_bad_json(self):
        req = urllib.request.Request(
            self.url("/api/audits"), data=b"not-json{",
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("应返回 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)


if __name__ == "__main__":
    unittest.main()
