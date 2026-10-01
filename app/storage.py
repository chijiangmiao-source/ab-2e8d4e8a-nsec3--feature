"""冻结结论的持久化存储：按稳定审计标识存取，检测标识复用/载荷篡改。"""

from __future__ import annotations

import json
import os
import threading
import time

from .verifier import payload_fingerprint


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            self._write({"audits": {}, "counter": 0})

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            return self._read()["audits"].get(audit_id)

    def list_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._read()["audits"].keys())

    def submit(self, result: dict) -> tuple[dict, str]:
        """冻结一次结论。

        返回 (stored_record, status)，status 为：
          frozen       —— 首次冻结
          unchanged    —— 同标识同载荷，返回原冻结结论（幂等）
          reuse        —— 同标识但载荷改变：拒绝，不覆盖原结论
        """
        with self._lock:
            data = self._read()
            audits = data["audits"]
            audit_id = result["audit_id"]
            fp = payload_fingerprint(result)
            existing = audits.get(audit_id)
            if existing is not None:
                if existing["fingerprint"] != fp:
                    conflict = {
                        "audit_id": audit_id,
                        "verdict": "rejected",
                        "reuse": True,
                        "message": (
                            "审计标识已被不同载荷使用：原结论保持冻结，"
                            f"原指纹 {existing['fingerprint'][:16]}…，本次指纹 {fp[:16]}…"
                        ),
                        "existing_frozen_at": existing.get("frozen_at"),
                        "fingerprint": fp,
                    }
                    return conflict, "reuse"
                return existing, "unchanged"
            data["counter"] += 1
            record = {
                "fingerprint": fp,
                "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "seq": data["counter"],
                "result": result,
            }
            audits[audit_id] = record
            self._write(data)
            return record, "frozen"
