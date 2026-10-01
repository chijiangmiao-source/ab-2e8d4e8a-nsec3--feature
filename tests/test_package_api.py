"""证据包 HTTP/JSON API 测试：冻结、重开、复用冲突、来源校验、不改写原审计。"""

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

EXISTING = [
    "example.cn", "a.example.cn", "m.example.cn",
    "z.example.cn", "x.y.example.cn",
]
T1 = "p.x.y.example.cn"
T2 = "g.x.y.example.cn"


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


class PackageApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        os.environ["AUDIT_DB"] = os.path.join(cls.tmpdir, "audits.json")
        cls.httpd = build_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.recs = build_chain(EXISTING)
        cls.source_payload = {
            "audit_id": "SRC-PKG", "zone": ZONE, "target": "q.example.cn",
            "salt": SALT, "iterations": ITER, "records": cls.recs,
        }
        status, body = cls._raw_request(
            "POST", "/api/audits", cls.source_payload)
        assert status == 200, body

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    @classmethod
    def _raw_request(cls, method, path, payload=None):
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"http://127.0.0.1:{cls.port}{path}", data=data, headers=headers,
            method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def request(self, method, path, payload=None):
        return self._raw_request(method, path, payload)

    def test_package_submit_pass_and_reopen(self):
        payload = {"package_id": "PKG-API-1",
                   "source_audit_id": "SRC-PKG", "targets": [T1, T2]}
        status, body = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "frozen")
        result = body["result"]
        self.assertEqual(result["verdict"], "passed")
        # 共享子集仅 2 条记录
        self.assertEqual(len(result["selected_records"]), 2)
        self.assertEqual(len(result["target_evidence"]), 2)
        self.assertEqual(len(result["unselected_records"]), 3)
        for te in result["target_evidence"]:
            self.assertTrue(te["closest_encloser"]["record_ref"])
            self.assertTrue(te["next_closer"]["covered_by"])
            self.assertTrue(te["wildcard"]["covered_by"])

        status, body = self.request("GET", "/api/packages?id=PKG-API-1")
        self.assertEqual(status, 200)
        self.assertTrue(body["found"])
        self.assertEqual(body["result"]["package_id"], "PKG-API-1")
        self.assertEqual(body["result"]["source_audit_id"], "SRC-PKG")

    def test_package_identical_is_unchanged(self):
        payload = {"package_id": "PKG-API-2",
                   "source_audit_id": "SRC-PKG", "targets": [T1, T2]}
        self.request("POST", "/api/packages", payload)
        status, body = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "unchanged")

    def test_package_id_reuse_target_change_conflict(self):
        p1 = {"package_id": "PKG-API-3", "source_audit_id": "SRC-PKG",
              "targets": [T1, T2]}
        self.request("POST", "/api/packages", p1)
        p2 = dict(p1, targets=[T1, "k.example.cn"])
        status, body = self.request("POST", "/api/packages", p2)
        self.assertEqual(status, 409)
        self.assertTrue(body["reuse"])
        # 原冻结结论保持不变
        _, body1 = self.request("GET", "/api/packages?id=PKG-API-3")
        self.assertEqual(body1["result"]["targets"], [T1, T2])

    def test_source_not_found_rejected(self):
        payload = {"package_id": "PKG-API-4",
                   "source_audit_id": "NOPE", "targets": [T1, T2]}
        status, body = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["errors"][0]["code"], "SOURCE_NOT_FOUND")

    def test_source_not_passed_rejected(self):
        bad_src = dict(self.source_payload, audit_id="SRC-PKG-BAD",
                       records=[r for r in self.recs
                                if r["owner_hash"] != H("m.example.cn")],
                       target="q.example.cn")
        status, body = self.request("POST", "/api/audits", bad_src)
        self.assertEqual(status, 422)
        payload = {"package_id": "PKG-API-5",
                   "source_audit_id": "SRC-PKG-BAD", "targets": [T1, T2]}
        status, body = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["errors"][0]["code"], "SOURCE_NOT_PASSED")

    def test_out_of_zone_and_duplicates_rejected(self):
        payload = {"package_id": "PKG-API-6", "source_audit_id": "SRC-PKG",
                   "targets": [T1, "x.other.net"]}
        status, body = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 422)
        codes = {e["code"] for e in body["result"]["errors"]}
        self.assertIn("OUT_OF_ZONE", codes)

        payload = {"package_id": "PKG-API-7", "source_audit_id": "SRC-PKG",
                   "targets": [T1, T1]}
        status, body = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 422)
        codes = {e["code"] for e in body["result"]["errors"]}
        self.assertIn("DUP_TARGET", codes)

    def test_source_audit_not_rewritten(self):
        _, before = self.request("GET", "/api/audits?id=SRC-PKG")
        payload = {"package_id": "PKG-API-8",
                   "source_audit_id": "SRC-PKG", "targets": [T1, T2]}
        self.request("POST", "/api/packages", payload)
        _, after = self.request("GET", "/api/audits?id=SRC-PKG")
        self.assertEqual(before["result"], after["result"])

    def test_list_and_unknown_package_404(self):
        status, body = self.request("GET", "/api/packages?id=NOPE-PKG")
        self.assertEqual(status, 404)
        self.assertFalse(body["found"])
        payload = {"package_id": "PKG-API-LIST",
                   "source_audit_id": "SRC-PKG", "targets": [T1, T2]}
        status, _ = self.request("POST", "/api/packages", payload)
        self.assertEqual(status, 200)
        status, body = self.request("GET", "/api/packages")
        self.assertEqual(status, 200)
        self.assertIn("PKG-API-LIST", body["package_ids"])


if __name__ == "__main__":
    unittest.main()
