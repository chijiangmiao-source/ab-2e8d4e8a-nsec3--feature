"""冻结结论的持久化存储：按稳定审计标识存取，检测标识复用/载荷篡改。

同一文件内分区保存：
  audits   —— 单目标 NSEC3 审计冻结结论
  packages —— 多目标共同记录证据包冻结结论（不可变快照，绝不回写 audits）
"""

from __future__ import annotations

import json
import os
import threading
import time

from .packages import package_fingerprint
from .verifier import payload_fingerprint


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            self._write({"audits": {}, "packages": {}, "counter": 0})

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("packages", {})
        return data

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

    # ── 多目标证据包 ─────────────────────────────────────────────
    def get_package(self, package_id: str) -> dict | None:
        with self._lock:
            return self._read()["packages"].get(package_id)

    def list_package_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._read()["packages"].keys())

    def submit_package(self, result: dict) -> tuple[dict, str]:
        """冻结一次证据包结论。

        返回 (stored_record, status)，status 为 frozen/unchanged/reuse，
        语义与 submit 相同；同标识改换来源审计或目标即 reuse，拒绝覆盖。
        """
        with self._lock:
            data = self._read()
            packages = data["packages"]
            package_id = result["package_id"]
            fp = package_fingerprint(result)
            existing = packages.get(package_id)
            if existing is not None:
                if existing["fingerprint"] != fp:
                    conflict = {
                        "package_id": package_id,
                        "verdict": "rejected",
                        "reuse": True,
                        "message": (
                            "证据包标识已被不同来源或不同目标使用：原冻结结论保持，"
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
            packages[package_id] = record
            self._write(data)
            return record, "frozen"
