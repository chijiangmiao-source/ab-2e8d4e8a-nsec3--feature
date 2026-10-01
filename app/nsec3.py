"""NSEC3 参数、记录解析与迭代哈希计算（仅支持 SHA-1、无 Opt-Out）。

参考：RFC 5155 §3.1.6 / §5 / §8.3。
Base32hex 定义见 §3.3：字母表 0-9a-v，小写规范、大写可接受。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

# 标准 base32 字母 A-Z2-7 与 base32hex 字母 0-9a-v 的互转表
_HEX_TO_STD = bytes.maketrans(
    b"0123456789abcdefghijklmnopqrstuv",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
)
_STD_TO_HEX = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    b"0123456789abcdefghijklmnopqrstuv",
)
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class AuditError(ValueError):
    """输入或证据非法（任何此类错误都意味着结论只能是 rejected）。"""


def normalise_domain(name: str) -> str:
    """归一化为小写、无尾点的 FQDN。"""
    if name is None:
        raise AuditError("域名为空")
    name = name.strip()
    if not name:
        raise AuditError("域名为空")
    if len(name) > 255:
        raise AuditError("域名总长超过 255 字节")
    labels = name.split(".")
    # 允许单个尾点（FQDN 写法），其余空标签（如 bad..name）一律非法
    if labels and labels[-1] == "":
        labels.pop()
    if not labels:
        raise AuditError("域名为根，不支持")
    if any(lab == "" for lab in labels):
        raise AuditError("域名包含空标签（连续句点）")
    out = []
    for label in labels:
        if not label.isascii():
            raise AuditError(f"非 ASCII 标签暂不支持: {label!r}")
        if len(label) > 63:
            raise AuditError(f"标签超过 63 字节: {label!r}")
        if not _LABEL_RE.match(label):
            raise AuditError(f"非法标签: {label!r}")
        out.append(label.lower())
    return ".".join(out)


def is_subdomain(name: str, zone: str) -> bool:
    if name == zone:
        return True
    return name.endswith("." + zone)


def split_labels(name: str) -> list[str]:
    return name.split(".") if name else []


def ancestor_chain(target: str, zone: str) -> list[str]:
    """目标在区内的祖先链：从目标自身逐层到 zone（含）。"""
    if not is_subdomain(target, zone):
        raise AuditError(f"目标 {target} 不在区域 {zone} 内")
    labels = split_labels(target)
    zlabels = split_labels(zone)
    chain = []
    for i in range(0, len(labels) - len(zlabels) + 1):
        chain.append(".".join(labels[i:]))
    return chain


def parent_of(name: str, zone: str) -> str | None:
    labels = split_labels(name)
    zlabels = split_labels(zone)
    if len(labels) <= len(zlabels):
        return None
    return ".".join(labels[1:])


def wildcard_child_of(name: str, zone: str) -> str | None:
    """name 之下一层的通配符名，即 *.name；若 name 之下即目标层以外则用于区间判定。

    对最近存在祖先 X，需要被 NSEC3 区间覆盖的通配符是 "*.<X>"（X 的直接子层）。
    """
    return "*." + name


def normalise_salt(salt: str) -> str:
    """归一化盐值：允许 '-'（无盐）与偶数位十六进制，返回小写十六进制。"""
    s = (salt or "").strip()
    if s == "-" or s == "":
        return "-"
    if len(s) % 2 != 0:
        raise AuditError("盐值十六进制长度为奇数")
    try:
        binascii.unhexlify(s)
    except (binascii.Error, ValueError):
        raise AuditError("盐值不是合法十六进制")
    return s.lower()


def nsec3_hash(name: str, salt_hex: str, iterations: int) -> str:
    """RFC 5155 §3.1.6 迭代哈希，返回小写 base32hex 串。"""
    if not isinstance(iterations, int) or iterations < 0 or iterations > 65535:
        raise AuditError("迭代次数须为 0..65535 的整数")
    salt = b"" if salt_hex == "-" else binascii.unhexlify(salt_hex)
    # 线格式：逐标签“长度字节 + 小写标签”，以 0 字节结尾
    wire = b"".join(
        bytes([len(lab)]) + lab.encode("ascii") for lab in name.split(".") if lab
    ) + b"\x00"
    digest = hashlib.sha1(wire + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    enc = base64.b32encode(digest)
    return enc.translate(_STD_TO_HEX).decode("ascii").rstrip("=").lower()


def b32hex_decode(text: str) -> bytes:
    """解码 NSEC3 owner/next 中的 base32hex 哈希标签。"""
    s = (text or "").strip().lower()
    if not s or not re.fullmatch(r"[0-9a-v]+", s):
        raise AuditError(f"非法 Base32hex: {text!r}")
    pad = b"=" * ((8 - len(s) % 8) % 8)
    try:
        raw = base64.b32decode(s.translate(_HEX_TO_STD).encode() + pad)
    except (binascii.Error, ValueError):
        raise AuditError(f"非法 Base32hex: {text!r}")
    if len(raw) != 20:
        raise AuditError(
            f"哈希长度应为 20 字节(SHA-1)，实为 {len(raw)} 字节: {text!r}"
        )
    return raw


def b32hex_canonical(text: str) -> str:
    """验证并归一化（解码后重新编码，消除大小写/填充歧义）。"""
    raw = b32hex_decode(text)
    return (
        base64.b32encode(raw)
        .translate(_STD_TO_HEX)
        .decode("ascii")
        .rstrip("=")
        .lower()
    )


def parse_type_bitmap(bitmap: str) -> list[str]:
    """解析 NSEC 类型位图文本（如 'NS SOA RRSIG' 或 'A,TXT'），去重排序。"""
    tokens = re.split(r"[\s,]+", (bitmap or "").strip())
    types = [t.upper() for t in tokens if t]
    for t in types:
        if not re.fullmatch(r"[A-Z][A-Z0-9]*", t):
            raise AuditError(f"非法类型位图条目: {t!r}")
    if len(types) != len(set(types)):
        raise AuditError("类型位图存在重复类型")
    return types
