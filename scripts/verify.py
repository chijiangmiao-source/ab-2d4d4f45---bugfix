"""Compose verify 验收组件的一键检查脚本。

在一次运行中依次核对：

1. 单元测试（``python -m unittest`` 全量）；
2. 构建检查（全部源码字节编译 + 关键模块导入）；
3. HTTP 冒烟（健康检查 + 六个必测场景）：
   a. 双类型重定位（R_X86_64_64 + R_X86_64_PC32）成功并逐项返回 S/A/P；
   b. 重叠写入被拒绝（patch_overlap）；
   c. PC32 有符号 32 位溢出被拒绝（pc32_overflow），且无部分结果；
   d. 扩展节编号（>=0xFF00，SHT_SYMTAB_SHNDX）文件中高编号 .text 符号
      与外部符号成功计算 S/A/P、写入字节与冻结摘要；
   e. 高编号非代码节定义符号被整体拒绝（symbol_not_in_text，可定位），
      同一稳定标识下旧成功结论被清除，且无任何部分补丁；
   f. 扩展索引元数据异常（长度不匹配/缺失）被可定位拒绝，无部分结果。

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

from elfbuild import build_elf, build_xindex_elf  # noqa: E402

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
    sources = (
        list((ROOT / "app").rglob("*.py"))
        + list((ROOT / "tests").rglob("*.py"))
        + [Path(__file__)]
    )
    for py in sources:
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


# --- 扩展节编号（节数 >= 0xFF00）样本 -------------------------------------

XBASE = 0x400000
XSYMS = {"ext_foo": 0x500000, "memcpy": 0x400200}


def xindex_good_elf() -> bytes:
    """高编号 .text(#0xFF00) 符号 + 外部符号，双类型重定位。"""
    return build_xindex_elf(
        text=bytes(range(48)),
        symbols=[
            ("ext_foo", "undef", 0),
            ("memcpy", "undef", 0),
            ("local_fn", "text", 0x10),
        ],
        relocs=[
            {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
            {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
            {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
        ],
    )


def xindex_noncode_elf() -> bytes:
    """第 1 项引用的本地符号定义在高编号非代码节 .rodata。"""
    return build_xindex_elf(
        symbols=[
            ("ext_foo", "undef", 0),
            ("data_obj", "rodata", 0),
        ],
        relocs=[
            {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
            {"offset": 0x08, "sym": 2, "type": 1, "addend": 0},
        ],
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

    # 场景 d：扩展节编号文件 —— 高编号 .text 符号与外部符号成功
    payload = {
        "audit_id": "verify-xindex-good",
        "file_base64": b64(xindex_good_elf()),
        "load_base": hex(XBASE),
        "symbols": XSYMS,
    }
    status, body = http_post("/api/audit", payload)
    if status != 200 or not body.get("ok"):
        fail(f"扩展编号高编号 .text 重定位应成功：HTTP {status} {body}")
    if len(body.get("items", [])) != 3:
        fail(f"应返回 3 个重定位项，实际 {len(body.get('items', []))}")
    by_off = {it["offset"]: it for it in body["items"]}
    r64 = by_off[0]
    # 外部符号逐字采用用户地址
    if r64["symbol"] != "ext_foo" or r64["S"] != "0x0000000000500000":
        fail(f"外部符号地址错误：{r64}")
    if r64["after_hex"] != struct.pack("<Q", 0x500010).hex():
        fail(f"R_X86_64_64 写入值错误：{r64['after_hex']}")
    local = by_off[0x10]
    # 高编号 .text(#0xFF00) 定义符号：S = base + st_value，差值为 0
    if local["symbol"] != "local_fn" or local["S"] != "0x0000000000400010":
        fail(f"高编号 .text 符号 S 计算错误：{local}")
    if local["P"] != "0x0000000000400010" or local["value"] != "0x00000000":
        fail(f"高编号 .text 符号 P/value 计算错误：{local}")
    if local["after_hex"] != struct.pack("<i", 0).hex():
        fail(f"高编号 .text 符号写入字节错误：{local['after_hex']}")
    for key in ("S", "A", "P", "value", "before_hex", "after_hex"):
        if key not in local:
            fail(f"成功结果缺少字段 {key}")
    if len(body.get("patched_sha256", "")) != 64 or len(body.get("conclusion", "")) != 64:
        fail("补丁摘要 / 冻结结论缺失")
    x_conclusion = body["conclusion"]
    status, fetched = http_get("/api/result/verify-xindex-good")
    if status != 200 or not fetched.get("ok") or fetched.get("conclusion") != x_conclusion:
        fail("扩展编号冻结结论无法按标识读回或不一致")
    print(f"verify: 扩展编号高 .text 重定位成功，结论 {x_conclusion}")

    # 场景 e：高编号非代码节符号整体拒绝，清除同一标识旧成功结论，无部分补丁
    payload = {
        "audit_id": "verify-xindex-good",  # 故意复用：旧 PASS 必须被清除
        "file_base64": b64(xindex_noncode_elf()),
        "load_base": hex(XBASE),
        "symbols": {"ext_foo": 0x500000},
    }
    status, body = http_post("/api/audit", payload)
    if status != 200 or body.get("ok"):
        fail(f"高编号非代码节符号应被拒绝：HTTP {status} {body}")
    v = body.get("violation", {})
    if v.get("code") != "symbol_not_in_text":
        fail(f"违约代码应为 symbol_not_in_text：{v}")
    if v.get("entry_index") != 1 or v.get("rela_index") != 1:
        fail(f"未稳定定位到非代码节违约项：{v}")
    if v.get("symbol") != "data_obj" or ".rodata" not in v.get("message", ""):
        fail(f"违约定位未指向高编号非代码节：{v}")
    for leaked in ("conclusion", "patches", "items", "patched_text_hex"):
        if leaked in body:
            fail(f"拒绝响应泄露部分结果字段 {leaked}")
    status, again = http_get("/api/result/verify-xindex-good")
    if status != 200 or again.get("ok") or "conclusion" in again:
        fail("同一标识下旧成功结论未被清除或仍可读到部分补丁")
    print("verify: 高编号非代码节符号已拒绝（symbol_not_in_text, entry_index=1），旧结论已清除")

    # 场景 f：扩展索引元数据异常（长度不匹配 / 关联错误 / 缺失）拒绝，无部分结果
    meta_cases = [
        ("short", "长度短于符号表", dict(xindex_size_mode="short"), "bad_symtab_shndx_length"),
        ("badlink", "关联错误", dict(xindex_link=3), "bad_symtab_shndx_link"),
        ("missing", "节缺失", dict(include_xindex=False), "bad_extended_symbol_index"),
    ]
    for case_id, label, kwargs, expect_code in meta_cases:
        bad = build_xindex_elf(
            text=bytes(range(48)),
            symbols=[
                ("ext_foo", "undef", 0),
                ("memcpy", "undef", 0),
                ("local_fn", "text", 0x10),
            ],
            relocs=[
                {"offset": 0x00, "sym": 1, "type": 1, "addend": 0x10},
                {"offset": 0x08, "sym": 2, "type": 2, "addend": -4},
                {"offset": 0x10, "sym": 3, "type": 2, "addend": 0},
            ],
            **kwargs,
        )
        payload = {
            "audit_id": f"verify-xindex-meta-{case_id}",
            "file_base64": b64(bad),
            "load_base": hex(XBASE),
            "symbols": XSYMS,
        }
        status, body = http_post("/api/audit", payload)
        if status != 200 or body.get("ok"):
            fail(f"扩展索引{label}应被拒绝：HTTP {status} {body}")
        if body["violation"].get("code") != expect_code:
            fail(f"扩展索引{label}违约代码应为 {expect_code}：{body['violation']}")
        for leaked in ("conclusion", "patches", "items", "patched_text_hex"):
            if leaked in body:
                fail(f"扩展索引{label}拒绝响应泄露部分结果字段 {leaked}")
        print(f"verify: 扩展索引{label}已拒绝（{expect_code}），无部分结果")


def main() -> None:
    print(f"verify: 目标服务 {BASE_URL}")
    check_unit_tests()
    check_build()
    check_http_smoke()
    print("\n=== verify: ALL CHECKS PASSED ===", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
