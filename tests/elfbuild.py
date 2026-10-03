"""测试夹具：在内存中手工构造 ELF64 小端 ET_REL 文件，不依赖外部工具链。"""

from __future__ import annotations

import struct

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_SYMTAB_SHNDX = 18

ET_REL = 1
EM_X86_64 = 62

R_X86_64_64 = 1
R_X86_64_PC32 = 2

STB_GLOBAL = 1
STT_NOTYPE = 0
STT_SECTION = 3

SHN_LORESERVE = 0xFF00
SHN_XINDEX = 0xFFFF


def _align(pos: int, align: int) -> int:
    if align <= 1:
        return pos
    return (pos + align - 1) // align * align


def _strtab(strings: list[bytes]) -> tuple[bytes, dict[int, int]]:
    blob = b"\x00"
    offsets: dict[int, int] = {}
    for i, s in enumerate(strings):
        offsets[i] = len(blob)
        blob += s + b"\x00"
    return blob, offsets


def build_elf(
    *,
    text: bytes = b"\x90" * 32,
    symbols: list[tuple[str, str | int, int]] | None = None,
    relocs: list[dict] | None = None,
    text_duplicate: bool = False,
    rodata: bytes | None = None,
    bss_size: int | None = None,
    rela_info: int | str | None = None,
    rela_type: int = SHT_RELA,
    second_rela: list[dict] | None = None,
    rela_bad_entsize: int | None = None,
    symtab_bad_entsize: int | None = None,
    e_type: int = ET_REL,
    e_machine: int = EM_X86_64,
    ei_class: int = 2,
    ei_data: int = 1,
    e_phoff: int = 0,
    shstrndx_valid: bool = True,
) -> bytes:
    """构造一个最小化 ET_REL。

    symbols 每项为 ``(名称, 所属节, st_value)``；所属节为 0 表示 SHN_UNDEF，
    ``"text"`` / ``"rodata"`` 表示对应节索引。
    relocs 每项为 ``{"offset","sym","type","addend"}``，sym 为 1 基符号序号
    （0 号为保留空符号）。
    """
    symbols = symbols or []
    relocs = relocs or []

    # ---- 节的逻辑布局：0=null, 1=.text[, 2=.text2], [.rodata], .strtab, .symtab, .rela.text, .shstrtab
    logical: list[dict] = []
    logical.append({"name": "", "type": 0})
    text_idx = len(logical)
    logical.append({"name": ".text", "type": SHT_PROGBITS, "data": text, "align": 16})
    if text_duplicate:
        logical.append({"name": ".text", "type": SHT_PROGBITS, "data": b"\xc3", "align": 16})
    rodata_idx: int | None = None
    if rodata is not None:
        rodata_idx = len(logical)
        logical.append({"name": ".rodata", "type": SHT_PROGBITS, "data": rodata, "align": 1})
    if bss_size is not None:
        logical.append({"name": ".bss", "type": 8, "data": b"", "size_override": bss_size, "align": 16})
    strtab_idx = len(logical)
    logical.append({"name": ".strtab", "type": SHT_STRTAB, "data": b"", "align": 1})
    symtab_idx = len(logical)
    logical.append({"name": ".symtab", "type": SHT_SYMTAB, "data": b"", "align": 8})
    rela_idx = len(logical)
    logical.append({"name": ".rela.text", "type": rela_type, "data": b"", "align": 8})
    rela2_idx: int | None = None
    if second_rela is not None:
        rela2_idx = len(logical)
        logical.append({"name": ".rela.text.alt", "type": rela_type, "data": b"", "align": 8})
    shstr_idx = len(logical)
    logical.append({"name": ".shstrtab", "type": SHT_STRTAB, "data": b"", "align": 1})

    def resolve_shndx(desc: str | int) -> int:
        if isinstance(desc, int):
            return desc
        return {"text": text_idx, "rodata": rodata_idx}[desc]  # type: ignore[index]

    # ---- 字符串表 / 符号表
    str_names = [s[0].encode("latin-1") for s in symbols]
    strtab_blob, str_offsets = _strtab(str_names)
    logical[strtab_idx]["data"] = strtab_blob

    sym_blob = b"\x00" * 24
    for i, (_name, sec_desc, value) in enumerate(symbols):
        info = (STB_GLOBAL << 4) | STT_NOTYPE
        shndx = resolve_shndx(sec_desc)
        sym_blob += struct.pack("<IBBHQQ", str_offsets[i], info, 0, shndx, value, 0)
    logical[symtab_idx]["data"] = sym_blob

    # ---- RELA / REL
    def encode_rela(relocs: list[dict]) -> bytes:
        blob = b""
        for r in relocs:
            r_info = (r["sym"] << 32) | (r["type"] & 0xFFFFFFFF)
            if rela_type == SHT_RELA:
                blob += struct.pack("<QQq", r["offset"], r_info, r.get("addend", 0))
            else:
                blob += struct.pack("<QQ", r["offset"], r_info)
        return blob

    logical[rela_idx]["data"] = encode_rela(relocs)
    if second_rela is not None:
        logical[rela2_idx]["data"] = encode_rela(second_rela)

    # ---- 节名字符串表
    shstr_blob = b"\x00"
    sh_name_offsets: dict[int, int] = {}
    for i, sec in enumerate(logical):
        sh_name_offsets[i] = 0
        if sec["name"]:
            sh_name_offsets[i] = len(shstr_blob)
            shstr_blob += sec["name"].encode() + b"\x00"
    logical[shstr_idx]["data"] = shstr_blob

    # ---- ELF 头 + 数据布局
    pos = 64
    for sec in logical[1:]:
        pos = _align(pos, sec.get("align", 1))
        sec["offset"] = pos
        sec["size"] = sec.get("size_override", len(sec["data"]))
        if sec["type"] != 8:  # SHT_NOBITS 不占文件空间
            pos += sec["size"]
    shoff = _align(pos, 8)

    # ---- 链接字段
    target = text_idx if rela_info is None else (resolve_shndx(rela_info) if isinstance(rela_info, str) else rela_info)
    logical[symtab_idx]["link"] = strtab_idx
    logical[symtab_idx]["info"] = 1  # 仅 null 符号（#0）为局部符号
    logical[symtab_idx]["entsize"] = symtab_bad_entsize if symtab_bad_entsize is not None else 24
    logical[rela_idx]["link"] = symtab_idx
    logical[rela_idx]["info"] = target
    logical[rela_idx]["entsize"] = (
        rela_bad_entsize if rela_bad_entsize is not None else (24 if rela_type == SHT_RELA else 16)
    )
    if second_rela is not None:
        logical[rela2_idx]["link"] = symtab_idx
        logical[rela2_idx]["info"] = target
        logical[rela2_idx]["entsize"] = 24 if rela_type == SHT_RELA else 16

    out = bytearray(shoff + len(logical) * 64)

    # ELF 头
    ei_ident = bytearray(16)
    ei_ident[0:4] = b"\x7fELF"
    ei_ident[4] = ei_class
    ei_ident[5] = ei_data
    ei_ident[6] = 1
    if ei_data == 2:  # 构造大端样本时使用大端打包
        ehdr = struct.pack(
            ">16sHHIQQQIHHHHHH",
            bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64, len(logical),
            shstr_idx if shstrndx_valid else 0xFFFE,
        )
    else:
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64, len(logical),
            shstr_idx if shstrndx_valid else 0xFFFE,
        )
    out[0:64] = ehdr

    for sec in logical[1:]:
        out[sec["offset"] : sec["offset"] + sec["size"]] = sec["data"]

    # 节头（构造大端样本时使用大端打包）
    for i, sec in enumerate(logical):
        if i == 0:
            continue
        shdr = struct.pack(
            (">IIQQQQIIQQ" if ei_data == 2 else "<IIQQQQIIQQ"),
            sh_name_offsets[i],
            sec["type"],
            0,
            0,
            sec["offset"],
            sec["size"],
            sec.get("link", 0),
            sec.get("info", 0),
            1,
            sec.get("entsize", 0),
        )
        out[shoff + i * 64 : shoff + (i + 1) * 64] = shdr

    return bytes(out)


def build_xindex_elf(
    *,
    text: bytes = b"\x00" * 32,
    rodata: bytes = b"RODATA!\x00",
    symbols: list[tuple[str, str, int]] | None = None,
    relocs: list[dict] | None = None,
    pad_count: int = 0xFF00 - 2,
    include_xindex: bool = True,
    xindex_link: int | None = None,
    xindex_entsize: int | None = None,
    xindex_size_mode: str = "ok",
    xindex_eof_truncated: bool = False,
    xindex_values: dict[int, int] | None = None,
    bad_extended_shstrndx: bool = False,
) -> bytes:
    """构造节数进入扩展编号范围（>= 0xFF00）的 ET_REL。

    逻辑布局（P = pad_count）：

        0=null；1..P=.p 占位 SHT_PROGBITS（零长，共享节名）；
        P+1=.rodata（非代码高编号节）；P+2=.text；P+3=.strtab；
        P+4=.symtab；P+5=.symtab_shndx；P+6=.rela.text；P+7=.shstrtab。

    symbols 每项 ``(名称, 目标, st_value)``，目标取值：

    * ``"undef"``：SHN_UNDEF 外部符号；
    * ``"text"``：st_shndx=SHN_XINDEX，扩展索引指向高编号 .text；
    * ``"rodata"``：st_shndx=SHN_XINDEX，扩展索引指向高编号非代码节。

    默认 P=0xFF00-2，使 .text 恰为节 #0xFF00、总节数 0xFF06，因此
    e_shnum 与 e_shstrndx 都必须使用扩展形式（0 / SHN_XINDEX）。

    扩展索引元数据可通过参数构造各类异常：``include_xindex=False`` 缺失、
    ``xindex_size_mode`` 为 short/extra/odd（长度不匹配/非 4 整数倍）、
    ``xindex_eof_truncated`` 数据区间越出文件、``xindex_link`` 关联错误、
    ``xindex_entsize`` 表项尺寸错误、``xindex_values`` 覆写单个表项取值。
    """
    symbols = symbols or []
    relocs = relocs or []

    n_pad = pad_count
    idx_rodata = n_pad + 1
    idx_text = n_pad + 2
    idx_strtab = n_pad + 3
    idx_symtab = n_pad + 4
    idx_xindex = n_pad + 5
    idx_rela = n_pad + 6
    idx_shstr = n_pad + 7
    nsec = n_pad + 8

    # ---- 数据布局（节头之前） ----
    pos = 64
    text_off = pos
    pos += len(text)
    rodata_off = pos
    pos += len(rodata)

    strtab_blob = b"\x00"
    str_offsets: list[int] = []
    for name, _target, _value in symbols:
        str_offsets.append(len(strtab_blob))
        strtab_blob += name.encode("latin-1") + b"\x00"
    strtab_off = pos
    pos += len(strtab_blob)

    sym_count = len(symbols) + 1
    symtab_blob = b"\x00" * 24
    for i, (_name, target, value) in enumerate(symbols):
        shndx = 0 if target == "undef" else SHN_XINDEX
        info = (STB_GLOBAL << 4) | STT_NOTYPE
        symtab_blob += struct.pack("<IBBHQQ", str_offsets[i], info, 0, shndx, value, 0)
    symtab_off = pos
    pos += len(symtab_blob)

    # 扩展索引表：与符号表一一对应
    xvalues: dict[int, int] = {0: 0}
    for i, (_name, target, _value) in enumerate(symbols, start=1):
        xvalues[i] = {"undef": 0, "text": idx_text, "rodata": idx_rodata}[target]
    if xindex_values:
        xvalues.update(xindex_values)
    xindex_words = b"".join(struct.pack("<I", xvalues[k]) for k in range(sym_count))
    # extra 模式额外追加一个字，保证缩短/增长时数据区仍在文件内
    xindex_blob = xindex_words + struct.pack("<I", 0)
    xindex_off = pos
    pos += len(xindex_blob)

    rela_blob = b""
    for r in relocs:
        r_info = (r["sym"] << 32) | (r["type"] & 0xFFFFFFFF)
        rela_blob += struct.pack("<QQq", r["offset"], r_info, r.get("addend", 0))
    rela_off = pos
    pos += len(rela_blob)

    shstr_blob = (
        b"\x00.p\x00.rodata\x00.text\x00.strtab\x00.symtab\x00"
        b".symtab_shndx\x00.rela.text\x00.shstrtab\x00"
    )
    name_pad = 1
    name_rodata = 4
    name_text = 12
    name_strtab = 18
    name_symtab = 26
    name_xindex = 34
    name_rela = 48
    name_shstr = 59
    shstr_off = pos
    pos += len(shstr_blob)

    shoff = (pos + 7) & ~7
    total = shoff + nsec * 64
    out = bytearray(total)

    # ---- ELF 头（扩展 e_shnum / e_shstrndx） ----
    ehdr_shnum = 0 if nsec >= SHN_LORESERVE else nsec
    ehdr_shstr = SHN_XINDEX if nsec >= SHN_LORESERVE else idx_shstr
    ei = bytearray(16)
    ei[0:4] = b"\x7fELF"
    ei[4], ei[5], ei[6] = 2, 1, 1
    out[0:64] = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ei), ET_REL, EM_X86_64, 1, 0, 0, shoff, 0, 64, 0, 0, 64,
        ehdr_shnum, ehdr_shstr,
    )

    # ---- 各节数据 ----
    out[text_off : text_off + len(text)] = text
    out[rodata_off : rodata_off + len(rodata)] = rodata
    out[strtab_off : strtab_off + len(strtab_blob)] = strtab_blob
    out[symtab_off : symtab_off + len(symtab_blob)] = symtab_blob
    out[xindex_off : xindex_off + len(xindex_blob)] = xindex_blob
    out[rela_off : rela_off + len(rela_blob)] = rela_blob
    out[shstr_off : shstr_off + len(shstr_blob)] = shstr_blob

    # ---- 第 0 节头：sh_size=真实节数；sh_link=真实 shstrndx ----
    sec0_link = nsec if bad_extended_shstrndx else idx_shstr
    struct.pack_into(
        "<IIQQQQIIQQ", out, shoff,
        0, 0, 0, 0, 0, nsec, sec0_link, 0, 0, 0,
    )

    def put_header(i: int, sh_name: int, sh_type: int, sh_offset: int, sh_size: int,
                   link: int = 0, info: int = 0, entsize: int = 0) -> None:
        struct.pack_into(
            "<IIQQQQIIQQ", out, shoff + i * 64,
            sh_name, sh_type, 0, 0, sh_offset, sh_size, link, info, 1, entsize,
        )

    # 占位节：零长 SHT_PROGBITS，共享同一节名
    pad_hdr = struct.pack("<IIQQQQIIQQ", name_pad, SHT_PROGBITS, 0, 0, 64, 0, 0, 0, 1, 0)
    for i in range(1, n_pad + 1):
        out[shoff + i * 64 : shoff + (i + 1) * 64] = pad_hdr

    put_header(idx_rodata, name_rodata, SHT_PROGBITS, rodata_off, len(rodata))
    put_header(idx_text, name_text, SHT_PROGBITS, text_off, len(text))
    put_header(idx_strtab, name_strtab, SHT_STRTAB, strtab_off, len(strtab_blob))
    put_header(idx_symtab, name_symtab, SHT_SYMTAB, symtab_off, len(symtab_blob),
               link=idx_strtab, info=1, entsize=24)

    xindex_size = {
        "ok": sym_count * 4,
        "short": (sym_count - 1) * 4,
        "extra": (sym_count + 1) * 4,
        "odd": sym_count * 4 + 2,
    }[xindex_size_mode]
    if include_xindex:
        x_off = total if xindex_eof_truncated else xindex_off
        put_header(
            idx_xindex, name_xindex, SHT_SYMTAB_SHNDX, x_off, xindex_size,
            link=idx_symtab if xindex_link is None else xindex_link,
            entsize=4 if xindex_entsize is None else xindex_entsize,
        )
    else:
        # 保留槽位但换成其他类型，模拟扩展索引节缺失（节编号不位移）
        put_header(idx_xindex, name_xindex, SHT_PROGBITS, xindex_off, 0)

    put_header(idx_rela, name_rela, SHT_RELA, rela_off, len(rela_blob),
               link=idx_symtab, info=idx_text, entsize=24)
    put_header(idx_shstr, name_shstr, SHT_STRTAB, shstr_off, len(shstr_blob))

    return bytes(out)
