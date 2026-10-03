"""扩展节编号（SHT_SYMTAB_SHNDX / SHN_XINDEX）审计测试。

覆盖供应商可提交的节数量进入 ELF 扩展编号范围（节数 >= 0xFF00，需同时使用
扩展 e_shnum、扩展 e_shstrndx 与 SHT_SYMTAB_SHNDX）的合法 ELF64 小端
ET_REL：

* 重定位引用的本地符号定义在高编号**非代码节**时必须整体拒绝，稳定定位
  该符号所在节，且不输出任何部分补丁；
* 高编号 .text 定义符号仍按既有规则成功计算 S/A/P、写入前后字节与冻结摘要；
* 高编号文件中的 SHN_UNDEF 外部符号继续使用用户提交的准确地址；
* 缺失、截断、长度不匹配、关联错误等扩展索引元数据问题必须可定位拒绝；
* 双类型重定位、重叠写入、PC32 溢出等既有规则不得回归。
"""

from __future__ import annotations

import base64
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import elfaudit
from app.server import run_audit
from elfbuild import build_xindex_elf

BASE = 0x400000
EXT_ADDR = {"ext_foo": 0x500000, "memcpy": 0x400200}

# 夹具默认 pad 布局：.text = #0xFF00，.rodata = #0xFEFF，总节数 0xFF06
TEXT_INDEX = 0xFF00
RODATA_INDEX = 0xFEFF


def syms_rodata() -> list[tuple[str, str, int]]:
    return [("ext_foo", "undef", 0), ("data_obj", "rodata", 0)]


def relocs_rodata() -> list[dict]:
    return [
        {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
        {"offset": 0x08, "sym": 2, "type": 1, "addend": 0},
    ]


def syms_text() -> list[tuple[str, str, int]]:
    return [("ext_foo", "undef", 0), ("memcpy", "undef", 0), ("local_fn", "text", 0x10)]


def relocs_text() -> list[dict]:
    return [
        {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
        {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
        {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
    ]


class ExtendedNumberingRejectTests(unittest.TestCase):
    def assertNoPartialResult(self, result) -> None:
        self.assertFalse(result.ok)
        self.assertEqual(result.items, [])
        self.assertEqual(result.patched, b"")
        self.assertEqual(result.patched_sha256, "")

    def test_symbol_in_high_noncode_section_rejected(self):
        elf = build_xindex_elf(
            text=bytes(range(32)),
            rodata=b"RODATA!\x00",
            symbols=syms_rodata(),
            relocs=relocs_rodata(),
        )
        result = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000})
        self.assertNoPartialResult(result)
        v = result.violation
        # 第 0 项引用的外部符号本可成功，仍必须在第 1 项的非代码节定位处整体拒绝
        self.assertEqual(v.code, "symbol_not_in_text")
        self.assertEqual(v.stage, "entry")
        self.assertEqual(v.entry_index, 1)
        self.assertEqual(v.rela_section, ".rela.text")
        self.assertEqual(v.rela_index, 1)
        self.assertEqual(v.symbol, "data_obj")
        self.assertIn(".rodata", v.message)
        self.assertIn(str(RODATA_INDEX), v.message)

    def test_first_violation_in_high_section_is_entry_zero(self):
        # 首个重定位项就引用高编号非代码节符号：定位必须落在 entry 0
        elf = build_xindex_elf(
            symbols=[("data_obj", "rodata", 0), ("ext_foo", "undef", 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 8, "sym": 2, "type": 1, "addend": 0},
            ],
        )
        v = elfaudit.audit(elf, BASE, {"ext_foo": 0x500000}).violation
        self.assertEqual(v.code, "symbol_not_in_text")
        self.assertEqual(v.entry_index, 0)
        self.assertEqual(v.symbol, "data_obj")

    def test_high_text_pc32_overflow_still_rejected(self):
        # 高编号 .text 文件不得让既有 PC32 溢出规则回归
        elf = build_xindex_elf(
            symbols=[("ext_foo", "undef", 0), ("local_fn", "text", 0x10)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 2, "addend": 0},
                {"offset": 8, "sym": 2, "type": 2, "addend": 0},
            ],
        )
        result = elfaudit.audit(elf, BASE, {"ext_foo": 0x7F0000000000})
        self.assertNoPartialResult(result)
        self.assertEqual(result.violation.code, "pc32_overflow")
        self.assertEqual(result.violation.entry_index, 0)

    def test_high_text_overlapping_writes_still_rejected(self):
        elf = build_xindex_elf(
            symbols=[("ext_foo", "undef", 0), ("memcpy", "undef", 0)],
            relocs=[
                {"offset": 0, "sym": 1, "type": 1, "addend": 0},
                {"offset": 4, "sym": 2, "type": 1, "addend": 0},
            ],
        )
        result = elfaudit.audit(elf, BASE, EXT_ADDR)
        self.assertNoPartialResult(result)
        self.assertEqual(result.violation.code, "patch_overlap")
        self.assertEqual(result.violation.entry_index, 1)


class ExtendedNumberingSuccessTests(unittest.TestCase):
    def test_high_text_and_external_symbols_compute(self):
        text = bytes(range(48))
        elf = build_xindex_elf(text=text, symbols=syms_text(), relocs=relocs_text())
        result = elfaudit.audit(elf, BASE, EXT_ADDR)
        self.assertTrue(result.ok, result.violation)
        self.assertEqual(len(result.items), 3)

        by_off = {it.offset: it for it in result.items}

        r64 = by_off[0x00]
        self.assertEqual(r64.reloc_type, 1)
        self.assertEqual(r64.symbol, "ext_foo")  # 外部符号使用用户准确地址
        self.assertEqual(r64.s, 0x500000)
        self.assertEqual(r64.a, 0x10)
        self.assertEqual(r64.p, BASE)
        self.assertEqual(r64.value, 0x500010)
        self.assertEqual(r64.before, bytes(range(8)))
        self.assertEqual(r64.after, struct.pack("<Q", 0x500010))

        pc_ext = by_off[0x08]
        self.assertEqual(pc_ext.symbol, "memcpy")
        self.assertEqual(pc_ext.s, 0x400200)  # 外部地址逐字采用，不做基址推导
        self.assertEqual(pc_ext.p, BASE + 8)
        self.assertEqual(pc_ext.value, 0x400200 - 4 - (BASE + 8))
        self.assertEqual(pc_ext.after, struct.pack("<i", pc_ext.value))

        local = by_off[0x10]  # 高编号 .text(#0xFF00) 定义符号
        self.assertEqual(local.symbol, "local_fn")
        self.assertEqual(local.s, BASE + 0x10)
        self.assertEqual(local.a, 0)
        self.assertEqual(local.p, BASE + 0x10)
        self.assertEqual(local.value, 0)
        self.assertEqual(local.after, struct.pack("<i", 0))

        # 补丁后节体与摘要
        patched = bytearray(text)
        patched[0:8] = struct.pack("<Q", 0x500010)
        patched[8:12] = struct.pack("<i", pc_ext.value)
        patched[0x10:0x14] = struct.pack("<i", 0)
        self.assertEqual(result.patched, bytes(patched))
        import hashlib

        self.assertEqual(result.patched_sha256, hashlib.sha256(bytes(patched)).hexdigest())

        # 冻结摘要稳定可复算，且与普通编号文件不同
        c1 = elfaudit.freeze_conclusion("xid", result, EXT_ADDR)
        c2 = elfaudit.freeze_conclusion("xid", elfaudit.audit(elf, BASE, EXT_ADDR), EXT_ADDR)
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 64)

    def test_external_symbol_exact_address_preserved(self):
        # 仅有高编号文件 + SHN_UNDEF 外部符号：地址必须逐字采用（含加数回绕）
        elf = build_xindex_elf(
            text=b"\x00" * 8,
            symbols=[("device_mmio", "undef", 0)],
            relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0x24}],
        )
        exact = 0xDEADBEEF0000
        result = elfaudit.audit(elf, BASE, {"device_mmio": exact})
        self.assertTrue(result.ok, result.violation)
        self.assertEqual(result.items[0].s, exact)
        self.assertEqual(result.items[0].value, (exact + 0x24) & ((1 << 64) - 1))


class ExtendedIndexMetadataTests(unittest.TestCase):
    def setUp(self):
        self.elf_ok_kwargs = dict(
            symbols=syms_text(),
            relocs=relocs_text(),
        )

    def _audit(self, elf: bytes, symbols=EXT_ADDR):
        return elfaudit.audit(elf, BASE, symbols)

    def test_missing_xindex_section_rejected(self):
        elf = build_xindex_elf(**self.elf_ok_kwargs, include_xindex=False)
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_extended_symbol_index")
        # 前两项为 SHN_UNDEF 外部符号，首个 SHN_XINDEX 符号 local_fn 位于第 2 项
        self.assertEqual(result.violation.entry_index, 2)
        self.assertEqual(result.items, [])

    def test_xindex_data_truncated_rejected(self):
        elf = build_xindex_elf(**self.elf_ok_kwargs, xindex_eof_truncated=True)
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.stage, "section")
        self.assertEqual(result.violation.code, "section_out_of_bounds")
        self.assertEqual(result.items, [])

    def test_xindex_length_short_and_extra_rejected(self):
        for mode in ("short", "extra"):
            with self.subTest(mode=mode):
                elf = build_xindex_elf(**self.elf_ok_kwargs, xindex_size_mode=mode)
                result = self._audit(elf)
                self.assertFalse(result.ok)
                self.assertEqual(result.violation.code, "bad_symtab_shndx_length")
                self.assertEqual(result.items, [])
                self.assertEqual(result.patched, b"")

    def test_xindex_size_not_multiple_of_4_rejected(self):
        elf = build_xindex_elf(**self.elf_ok_kwargs, xindex_size_mode="odd")
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_symtab_shndx_size")
        self.assertEqual(result.items, [])

    def test_xindex_wrong_association_rejected(self):
        elf = build_xindex_elf(**self.elf_ok_kwargs, xindex_link=3)
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_symtab_shndx_link")
        self.assertEqual(result.items, [])

    def test_xindex_bad_entsize_rejected(self):
        elf = build_xindex_elf(**self.elf_ok_kwargs, xindex_entsize=8)
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_symtab_shndx_entsize")
        self.assertEqual(result.items, [])

    def test_xindex_entry_out_of_section_range_rejected(self):
        # 扩展表存在且长度正确，但表项指向不存在的节
        elf = build_xindex_elf(**self.elf_ok_kwargs, xindex_values={3: 0xFFF0})
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_extended_symbol_index")
        self.assertEqual(result.violation.stage, "section")
        self.assertEqual(result.violation.detail.get("index_entry"), 3)
        self.assertEqual(result.items, [])

    def test_extended_shstrndx_out_of_range_rejected(self):
        elf = build_xindex_elf(**self.elf_ok_kwargs, bad_extended_shstrndx=True)
        result = self._audit(elf)
        self.assertFalse(result.ok)
        self.assertEqual(result.violation.code, "bad_shstrndx")
        self.assertEqual(result.items, [])


class ExtendedNumberingApiTests(unittest.TestCase):
    def setUp(self):
        from app import server

        server._store.clear()

    def _payload(self, elf: bytes, audit_id: str, symbols=EXT_ADDR) -> dict:
        return {
            "audit_id": audit_id,
            "file_base64": base64.b64encode(elf).decode(),
            "load_base": hex(BASE),
            "symbols": symbols,
        }

    def test_noncode_rejection_clears_prior_success(self):
        from app import server

        # 1) 高编号 .text 文件先成功并冻结结论
        good = build_xindex_elf(text=bytes(range(48)), symbols=syms_text(), relocs=relocs_text())
        ok = run_audit(self._payload(good, "xid-stable"))
        self.assertTrue(ok["ok"])
        self.assertEqual(len(ok["conclusion"]), 64)
        conclusion = ok["conclusion"]

        # 2) 同一稳定标识提交高编号非代码节违约文件
        bad = build_xindex_elf(symbols=syms_rodata(), relocs=relocs_rodata())
        fail = run_audit(self._payload(bad, "xid-stable", symbols={"ext_foo": 0x500000}))
        self.assertFalse(fail["ok"])
        v = fail["violation"]
        self.assertEqual(v["code"], "symbol_not_in_text")
        self.assertEqual(v["entry_index"], 1)
        self.assertEqual(v["symbol"], "data_obj")
        # 拒绝响应不得携带任何成功产物
        self.assertNotIn("conclusion", fail)
        self.assertNotIn("patches", fail)
        self.assertNotIn("patched_text_hex", fail)

        # 3) 存储中旧成功结论已被清除
        stored = server._store["xid-stable"]
        self.assertEqual(stored["kind"], "fail")
        self.assertNotIn("result", stored)
        self.assertNotIn("conclusion", stored)

        # 4) 再提交一次合法文件，结论必须能重新建立（证明标识可重入）
        again = run_audit(self._payload(good, "xid-stable"))
        self.assertTrue(again["ok"])
        self.assertEqual(again["conclusion"], conclusion)

    def test_metadata_failure_leaves_no_recorded_patch(self):
        from app import server

        # 先成功
        good = build_xindex_elf(text=bytes(range(48)), symbols=syms_text(), relocs=relocs_text())
        self.assertTrue(run_audit(self._payload(good, "xid-meta"))["ok"])
        # 再提交扩展索引截断的文件：整体拒绝，旧结论清除
        bad = build_xindex_elf(symbols=syms_text(), relocs=relocs_text(), xindex_size_mode="short")
        fail = run_audit(self._payload(bad, "xid-meta"))
        self.assertFalse(fail["ok"])
        self.assertEqual(fail["violation"]["code"], "bad_symtab_shndx_length")
        stored = server._store["xid-meta"]
        self.assertEqual(stored["kind"], "fail")
        self.assertNotIn("patched_text_hex", stored)


if __name__ == "__main__":
    unittest.main(verbosity=2)
