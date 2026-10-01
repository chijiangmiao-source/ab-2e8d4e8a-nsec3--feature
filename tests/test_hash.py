"""哈希与解析单元测试：与 dnspython（若可用）交叉校验，否则使用固定向量。"""

import unittest

from app.nsec3 import (
    AuditError,
    ancestor_chain,
    b32hex_canonical,
    b32hex_decode,
    normalise_domain,
    normalise_salt,
    nsec3_hash,
    parse_type_bitmap,
)

# 由 dnspython 2.x dns.dnssec.nsec3_hash 生成的参考向量（SHA-1）
VECTORS = [
    ("example", "a5cba327531740b3", 0, "obruu6o5glqiqcsjf3c8dmb063m5rtbe"),
    ("example", "a5cba327531740b3", 12, "o9cpger98bqpt42kavir6q2n0i1gp7va"),
    ("example", "-", 0, "3msev9usmd4br9s97v51r2tdvmr9iqo1"),
    ("*.example", "a5cba327531740b3", 12, "hn153potppi9409jd6lgne0ntep9isd3"),
    ("x.y.example", "-", 5, "s24c8r025sscq6qug2le93t6fnbcenhp"),
    ("ns1.example", "a5cba327531740b3", 12, "i9567lum492err4gffr3f5tea4nn05am"),
]


class HashTests(unittest.TestCase):
    def test_vectors(self):
        for name, salt, iters, expected in VECTORS:
            with self.subTest(name=name, salt=salt, iters=iters):
                self.assertEqual(nsec3_hash(name, salt, iters), expected)

    def test_cross_check_dnspython(self):
        try:
            import dns.dnssec
            import dns.name
        except ImportError:
            self.skipTest("dnspython 未安装，跳过交叉校验")
        for name, salt, iters, _ in VECTORS:
            sb = None if salt == "-" else bytes.fromhex(salt)
            ref = dns.dnssec.nsec3_hash(
                dns.name.from_text(name + "."), sb, iters, "SHA1"
            ).lower()
            self.assertEqual(nsec3_hash(name, salt, iters), ref)

    def test_uppercase_b32_accepted(self):
        h = nsec3_hash("example", "-", 0)
        self.assertEqual(b32hex_canonical(h.upper()), h)

    def test_bad_b32(self):
        for bad in ("", "w", "zz", "12345=", "0p9mHAVEQVM"):
            with self.subTest(bad=bad):
                with self.assertRaises(AuditError):
                    b32hex_decode(bad)

    def test_b32_length(self):
        # 32 个 base32hex 字符=20 字节；31 字符不是 SHA-1 长度
        with self.assertRaises(AuditError):
            b32hex_decode("0" * 31)
        self.assertEqual(len(b32hex_decode("0" * 32)), 20)

    def test_salt(self):
        self.assertEqual(normalise_salt(""), "-")
        self.assertEqual(normalise_salt("-"), "-")
        self.assertEqual(normalise_salt("ABCD"), "abcd")
        with self.assertRaises(AuditError):
            normalise_salt("abc")
        with self.assertRaises(AuditError):
            normalise_salt("zz")

    def test_domain(self):
        self.assertEqual(normalise_domain("Host.Example.CN."), "host.example.cn")
        with self.assertRaises(AuditError):
            normalise_domain("bad..name")
        with self.assertRaises(AuditError):
            normalise_domain("-bad.example")

    def test_ancestor_chain(self):
        chain = ancestor_chain("a.b.example.cn", "example.cn")
        self.assertEqual(
            chain, ["a.b.example.cn", "b.example.cn", "example.cn"]
        )

    def test_bitmap(self):
        self.assertEqual(parse_type_bitmap("NS, soa RRSIG"), ["NS", "SOA", "RRSIG"])
        with self.assertRaises(AuditError):
            parse_type_bitmap("NS NS")


if __name__ == "__main__":
    unittest.main()
