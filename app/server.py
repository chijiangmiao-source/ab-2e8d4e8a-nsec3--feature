"""纯标准库 HTTP 服务：审计页面 + 冻结结论 JSON API + 健康检查。"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .storage import Store
from .verifier import verify

_STORE_LOCK = threading.Lock()
_STORE: Store | None = None
_PAGE_CACHE: str | None = None


def get_store() -> Store:
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                _STORE = Store(os.environ.get("AUDIT_DB", "/data/audits.json"))
    return _STORE


def _index_page() -> str:
    global _PAGE_CACHE
    if _PAGE_CACHE is None:
        path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
        with open(path, "r", encoding="utf-8") as fh:
            _PAGE_CACHE = fh.read()
    return _PAGE_CACHE


class Handler(BaseHTTPRequestHandler):
    server_version = "NSEC3Audit/1.0"

    def log_message(self, fmt, *args):  # 简洁日志
        import sys

        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self._send_json({"status": "ok", "service": "nsec3-audit"})
            return
        if path == "/api/audits":
            qs = parse_qs(parsed.query)
            audit_id = (qs.get("id") or [""])[0].strip()
            if not audit_id:
                self._send_json({"audit_ids": get_store().list_ids()})
                return
            record = get_store().get(audit_id)
            if record is None:
                self._send_json(
                    {"audit_id": audit_id, "found": False,
                     "message": "未找到该审计标识的冻结结论"},
                    status=404,
                )
                return
            out = {"found": True, "status": "frozen", **record}
            self._send_json(out)
            return
        if path in ("/", "/index.html", "/audit"):
            body = _index_page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/audits":
            self._send_json({"error": "not found"}, status=404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            self._send_json({"verdict": "rejected", "errors": [
                {"code": "BAD_REQUEST", "message": "请求体为空或过大"}]}, status=400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            self._send_json({"verdict": "rejected", "errors": [
                {"code": "BAD_JSON", "message": "请求体不是合法 JSON 对象"}]}, status=400)
            return
        result = verify(payload)
        record, status = get_store().submit(result)
        if status == "reuse":
            self._send_json(record, status=409)
            return
        out = {"found": True, "status": status, **record}
        self._send_json(out, status=200 if result["verdict"] == "passed" else 422)


def build_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    port = port or int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    return httpd


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    httpd = build_server(port=port)
    print(f"NSEC3 audit service listening on 0.0.0.0:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
