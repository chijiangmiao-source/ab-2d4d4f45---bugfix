"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. HTTP 冒烟（健康检查 + 六个必测场景）：
   a. 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. 重叠写入被拒绝（patch_overlap）；
   c. PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果；
   d. 节数量进入扩展编号范围（>=0xFF00）的高编号 .text 定义符号成功
      重定位，逐项返回 S/A/P 与写入前后字节、冻结摘要；
   e. 同一稳定标识提交高编号非代码节定义符号时整体拒绝
      （symbol_not_in_text），旧成功结论被清除，且无任何部分补丁；
   f. 异常扩展索引元数据（缺失 / 长度不匹配 / 关联错误 / 重复 / 截断）
      全部得到可定位拒绝，不产生部分结果；高编号未定义外部符号继续使用
      用户提交的准确地址。

任何一步失败立即以非零退出码结束；全部成功退出码为 0。
"""

from __future__ import annotations

import base64
import json
import os
import py_compile
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from elfbuild import build_elf  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
TIMEOUT = 5


def step(name: str) -> None:
    print(f"\n=== verify: {name} ===", flush=True)


def fail(msg: str) -> None:
    print(f"verify: FAIL — {msg}", flush=True)
    sys.exit(1)


def check_unit_tests() -> None:
    step("1/3 单元测试")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail(f"单元测试失败（退出码 {proc.returncode}）")
    print("verify: 单元测试全部通过")


def check_build() -> None:
    step("2/3 构建检查（字节编译 + 模块导入）")
    for py in list((ROOT / "app").rglob("*.py")) + [Path(__file__)]:
        try:
            py_compile.compile(str(py), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"字节编译失败 {py}: {exc}")
    proc = subprocess.run(
        [sys.executable, "-c", "import app.server, app.elfaudit; print('import ok')"],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fail("关键模块导入失败")
    # 静态资源（页面）必须存在
    page = ROOT / "app" / "static" / "index.html"
    if not page.is_file() or page.stat().st_size == 0:
        fail("审计页面 app/static/index.html 缺失或为空")
    print("verify: 构建检查通过")


def http_get(path: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(BASE_URL + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            body = json.loads(raw) if "application/json" in ctype else None
            return resp.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        ctype = exc.headers.get("Content-Type", "")
        body = json.loads(raw) if "application/json" in ctype else None
        return exc.code, body


def http_post(path: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health(attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            status, body = http_get("/healthz")
            if status == 200 and body and body.get("status") == "ok":
                print(f"verify: 健康检查通过 {BASE_URL}/healthz -> {body}")
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    fail(f"服务在 {attempts}s 内未通过健康检查：{BASE_URL}/healthz")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def double_type_elf() -> bytes:
    return build_elf(
        text=bytes(range(48)),
        symbols=[
            ("ext_foo", 0, 0),
            ("memcpy", 0, 0),
            ("local_fn", "text", 0x10),
        ],
        relocs=[
            {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
            {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
            {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
        ],
    )


def overlap_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("memcpy", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},  # [0,8)
            {"offset": 4, "sym": 2, "type": 2, "addend": 0},  # [4,8) 重叠
        ],
    )


def pc32_overflow_elf() -> bytes:
    return build_elf(
        text=b"\x00" * 32,
        symbols=[("ext_foo", 0, 0), ("far_away", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0},
            {"offset": 8, "sym": 2, "type": 2, "addend": 0},
        ],
    )


# 节数量进入扩展编号范围（>=0xFF00）的目标文件：.text=0xFF01，.data=0xFF02
HIGH_TEXT = b"\x90" * 32
HIGH_SECTIONS = {0xFF01: (".text", HIGH_TEXT), 0xFF02: (".data", b"ABCD")}


def high_text_elf() -> bytes:
    """高编号 .text 定义符号 + 高编号未定义外部符号。"""
    return build_elf(
        text=HIGH_TEXT,
        high_sections=dict(HIGH_SECTIONS),
        symbols=[("fn_high", 0xFF01, 0x10), ("ext_foo", 0, 0)],
        relocs=[
            {"offset": 0, "sym": 1, "type": 1, "addend": 0x8},
            {"offset": 8, "sym": 2, "type": 1, "addend": 0},
        ],
        xindex={1: 0xFF01},
    )


def high_noncode_elf() -> bytes:
    """重定位引用的本地符号定义在高编号非代码节 .data。"""
    return build_elf(
        text=HIGH_TEXT,
        high_sections=dict(HIGH_SECTIONS),
        symbols=[("d_in_data", 0xFF02, 2)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        xindex={1: 0xFF02},
    )


def bad_xindex_elf(xindex_values=None, **kw) -> bytes:
    return build_elf(
        text=HIGH_TEXT,
        high_sections=dict(HIGH_SECTIONS),
        symbols=[("fn_high", 0xFF01, 0x10)],
        relocs=[{"offset": 0, "sym": 1, "type": 1, "addend": 0}],
        xindex={1: 0xFF01} if xindex_values is None else xindex_values,
        **kw,
    )


def check_http_smoke() -> None:
    step("3/3 HTTP 冒烟")
    wait_for_health()

    # 页面可访问且包含审计台标记
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=TIMEOUT) as resp:
            page = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        page = ""
    if status != 200 or "ELF64" not in page:
        fail(f"审计页面异常：HTTP {status}")
    print("verify: 页面 GET / -> 200")

    # 场景 a：双类型重定位成功
    payload = {
        "audit_id": "verify-double-type",
        "file_base64": b64(double_type_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body = http_post("/api/audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"双类型重定位应成功：HTTP {status} {body}")
    if len(body.get("items", [])) != 3:
        fail(f"应返回 3 个重定位项，实际 {len(body.get('items', []))}")
    types = sorted(it["type_name"] for it in body["items"])
    if types != ["R_X86_64_64", "R_X86_64_PC32", "R_X86_64_PC32"]:
        fail(f"重定位类型集合异常：{types}")
    r64 = next(it for it in body["items"] if it["type_name"] == "R_X86_64_64")
    for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
        if key not in r64:
            fail(f"成功结果缺少字段 {key}")
    if r64["after_hex"] != struct.pack("<Q", 0x500010).hex():
        fail(f"R_X86_64_64 写入值错误：{r64['after_hex']}")
    offsets = [p["offset"] for p in body["patches"]]
    if offsets != sorted(offsets):
        fail("补丁未按偏移排序")
    if len(body.get("conclusion", "")) != 64:
        fail("冻结结论 SHA-256 缺失")
    print(f"verify: 双类型重定位成功，结论 {body['conclusion']}")

    # 冻结结论可凭标识读回
    status, fetched = http_get("/api/result/verify-double-type")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != body["conclusion"]:
        fail("冻结结论无法按标识读回或内容不一致")
    print("verify: 冻结结论读回一致")

    # 场景 b：重叠写入拒绝，且清除旧成功结论（使用同一标识）
    payload_b = {
        "audit_id": "verify-double-type",  # 故意复用：旧 PASS 必须被清除
        "file_base64": b64(overlap_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "memcpy": 0x400200},
    }
    status, body_b = http_post("/api/audit", payload_b)
    if status != 200 or body_b.get("ok"):
        fail(f"重叠写入应被拒绝：HTTP {status} {body_b}")
    if body_b["violation"]["code"] != "patch_overlap":
        fail(f"违约代码应为 patch_overlap：{body_b['violation']}")
    if body_b["violation"].get("entry_index") != 1:
        fail("未定位到首个违约项（entry_index 应为 1）")
    if "conclusion" in body_b:
        fail("拒绝响应中不得携带旧冻结结论")
    status, again = http_get("/api/result/verify-double-type")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("旧成功结论未被清除")
    print("verify: 重叠写入已拒绝，首个违约项 entry_index=1，旧成功结论已清除")

    # 场景 c：PC32 溢出拒绝，无部分结果
    payload_c = {
        "audit_id": "verify-pc32-overflow",
        "file_base64": b64(pc32_overflow_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000, "far_away": 0x7F0000000000},
    }
    status, body_c = http_post("/api/audit", payload_c)
    if status != 200 or body_c.get("ok"):
        fail(f"PC32 溢出应被拒绝：HTTP {status} {body_c}")
    if body_c["violation"]["code"] != "pc32_overflow":
        fail(f"违约代码应为 pc32_overflow：{body_c['violation']}")
    if body_c["violation"].get("entry_index") != 1:
        fail("PC32 溢出未定位到首个违约项（entry_index 应为 1）")
    status, stored = http_get("/api/result/verify-pc32-overflow")
    if status != 200 or stored.get("ok"):
        fail("溢出记录不应包含成功结论/部分补丁")
    print("verify: PC32 有符号 32 位溢出已拒绝，未生成部分结果")

    # 场景 d：高编号 .text 定义符号成功重定位（外部符号使用精确地址）
    payload_d = {
        "audit_id": "verify-high-text",
        "file_base64": b64(high_text_elf()),
        "load_base": 0x400000,
        "symbols": {"ext_foo": 0x500000},
    }
    status, body_d = http_post("/api/audit", payload_d)
    if status != 200 or not body_d.get("ok"):
        fail(f"高编号 .text 符号重定位应成功：HTTP {status} {body_d}")
    items_d = body_d.get("items", [])
    if len(items_d) != 2:
        fail(f"高编号文件应返回 2 个重定位项，实际 {len(items_d)}")
    by_sym = {it["symbol"]: it for it in items_d}
    fn_item = by_sym["fn_high"]
    if fn_item["S"] != f"0x{0x400010:016x}":
        fail(f"高编号 .text 符号 S 计算错误：{fn_item['S']}")
    if fn_item["A"] != "8" or fn_item["P"] != f"0x{0x400000:016x}":
        fail(f"高编号 .text 符号 A/P 错误：A={fn_item['A']} P={fn_item['P']}")
    if fn_item["after_hex"] != struct.pack("<Q", 0x400018).hex():
        fail(f"高编号 .text 符号写入值错误：{fn_item['after_hex']}")
    if fn_item["before_hex"] != (b"\x90" * 8).hex():
        fail("高编号 .text 符号写入前字节错误")
    ext_item = by_sym["ext_foo"]
    if ext_item["S"] != f"0x{0x500000:016x}" or ext_item["after_hex"] != struct.pack("<Q", 0x500000).hex():
        fail("高编号未定义外部符号未使用用户提交的准确地址")
    if len(body_d.get("conclusion", "")) != 64:
        fail("高编号成功结果缺少 64 字符冻结结论")
    if len(body_d.get("text_sha256_before", "")) != 64 or len(body_d.get("patched_sha256", "")) != 64:
        fail("高编号成功结果缺少补丁前后 .text 摘要")
    status, fetched_d = http_get("/api/result/verify-high-text")
    if status != 200 or fetched_d.get("conclusion") != body_d["conclusion"]:
        fail("高编号冻结结论无法按标识读回")
    print(f"verify: 高编号 .text 符号重定位成功，结论 {body_d['conclusion']}")

    # 场景 e：同一稳定标识提交高编号非代码节定义符号 -> 整体拒绝并清除旧成功
    payload_e = {
        "audit_id": "verify-high-text",  # 复用：旧 PASS 必须被清除
        "file_base64": b64(high_noncode_elf()),
        "load_base": 0x400000,
        "symbols": {},
    }
    status, body_e = http_post("/api/audit", payload_e)
    if status != 200 or body_e.get("ok"):
        fail(f"高编号非代码节符号应被拒绝：HTTP {status} {body_e}")
    ve = body_e.get("violation", {})
    if ve.get("code") != "symbol_not_in_text":
        fail(f"违约代码应为 symbol_not_in_text：{ve}")
    if ve.get("entry_index") != 0 or ve.get("symbol") != "d_in_data":
        fail(f"未稳定定位到违规符号：{ve}")
    if ve.get("detail", {}).get("shndx") != 0xFF02:
        fail(f"违约定位未给出高编号非代码节索引：{ve}")
    for leaked in ("conclusion", "patches", "items", "patched_text_hex"):
        if leaked in body_e:
            fail(f"拒绝响应泄露部分结果字段：{leaked}")
    status, again_e = http_get("/api/result/verify-high-text")
    if status != 200 or again_e.get("ok") or "conclusion" in again_e:
        fail("高编号拒绝后旧成功结论未被清除或仍可读出部分结果")
    print("verify: 高编号非代码节符号已稳定拒绝（shndx=0xff02），旧成功结论已清除，无部分补丁")

    # 场景 f：异常扩展索引元数据 -> 可定位拒绝，且不产生部分结果
    bad_cases = [
        ("缺失扩展索引节", bad_xindex_elf(xindex_emit=False), "missing_xindex_section"),
        ("扩展索引长度不足", bad_xindex_elf(xindex_count_delta=-1), "bad_xindex_length"),
        ("扩展索引长度过长", bad_xindex_elf(xindex_count_delta=2), "bad_xindex_length"),
        ("扩展索引长度非 4 倍数", bad_xindex_elf(xindex_bad_size=True), "bad_xindex_size"),
        ("扩展索引关联错误", bad_xindex_elf(xindex_link_override=1), "bad_xindex_link"),
        ("扩展索引节重复", bad_xindex_elf(xindex_duplicate=True), "xindex_not_unique"),
        ("扩展索引值仍为 0xffff", bad_xindex_elf(xindex_values={1: 0xFFFF}),
         "bad_extended_symbol_index"),
    ]
    for label, elf_bytes, expect_code in bad_cases:
        payload_f = {
            "audit_id": "verify-bad-xindex",
            "file_base64": b64(elf_bytes),
            "load_base": 0x400000,
            "symbols": {},
        }
        status, body_f = http_post("/api/audit", payload_f)
        if status != 200 or body_f.get("ok"):
            fail(f"{label}：应被拒绝：HTTP {status} {body_f}")
        vf = body_f.get("violation", {})
        if vf.get("code") != expect_code:
            fail(f"{label}：违约代码应为 {expect_code}，实际 {vf.get('code')}")
        for leaked in ("conclusion", "patches", "items", "patched_text_hex"):
            if leaked in body_f:
                fail(f"{label}：拒绝响应泄露部分结果字段 {leaked}")
    status, stored_f = http_get("/api/result/verify-bad-xindex")
    if status != 200 or stored_f.get("ok") or "conclusion" in stored_f:
        fail("异常索引元数据的拒绝记录不得包含成功结论/部分补丁")
    print(f"verify: {len(bad_cases)} 类异常扩展索引元数据全部可定位拒绝，无部分结果")


def main() -> None:
    print(f"verify: 目标服务 {BASE_URL}")
    check_unit_tests()
    check_build()
    check_http_smoke()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
