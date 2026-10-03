"""测试夹具：在内存中手工构造 ELF64 小端 ET_REL 文件，不依赖外部工具链。"""

from __future__ import annotations

import struct

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
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
    xindex: dict[int, int] | None = None,
    xindex_emit: bool = True,
    xindex_link_override: int | None = None,
    xindex_count_delta: int = 0,
    xindex_bad_size: bool = False,
    xindex_duplicate: bool = False,
    high_sections: dict[int, tuple[str, bytes]] | None = None,
) -> bytes:
    """构造一个最小化 ET_REL。

    symbols 每项为 ``(名称, 所属节, st_value)``；所属节为 0 表示 SHN_UNDEF，
    ``"text"`` / ``"rodata"`` 表示对应节索引。
    relocs 每项为 ``{"offset","sym","type","addend"}``，sym 为 1 基符号序号
    （0 号为保留空符号）。

    扩展节索引相关参数：

    * ``xindex``：``{符号 1 基序号: 真实节索引}``；命中的符号 st_shndx 写
      SHN_XINDEX(0xffff)，并生成与之平行的 SHT_SYMTAB_SHNDX 节；
    * ``xindex_emit=False``：只把 st_shndx 写成 0xffff，不生成扩展节（缺失）；
    * ``xindex_link_override``：篡改扩展节的 sh_link（关联错误）；
    * ``xindex_count_delta``：扩展节表项数相对符号表项数的增减（长度不匹配）；
    * ``xindex_bad_size``：令扩展节字节数不是 4 的整数倍（截断/畸形）；
    * ``xindex_duplicate``：生成两个关联同一符号表的扩展节（不唯一）；
    * ``high_sections``：``{绝对节索引: (名称, 数据[, 节类型])}``，用于构造
      节数量进入扩展编号范围（>= SHN_LORESERVE）的目标文件；中间以空
      PROGBITS 节填充，节类型缺省为 SHT_PROGBITS（可传 8=SHT_NOBITS 等）。
    """
    symbols = symbols or []
    relocs = relocs or []

    # ---- 节的逻辑布局：0=null, 1=.text[, 2=.text2], [.rodata], .strtab, .symtab, .rela.text, .shstrtab
    logical: list[dict] = []
    logical.append({"name": "", "type": 0})

    need_xindex = xindex is not None and xindex_emit
    high_mode = high_sections is not None

    def append_padding(up_to_exclusive: int) -> None:
        """用 1 字节 PROGBITS 占节填充，使下一个节的逻辑索引达到指定值。"""
        while len(logical) < up_to_exclusive:
            logical.append(
                {
                    "name": f".pad{len(logical)}",
                    "type": SHT_PROGBITS,
                    "data": b"\x00",
                    "align": 1,
                }
            )

    def append_text_section(text_data: bytes) -> int:
        idx = len(logical)
        logical.append({"name": ".text", "type": SHT_PROGBITS, "data": text_data, "align": 16})
        return idx

    text_idx: int
    rodata_idx: int | None = None
    strtab_idx: int
    symtab_idx: int
    rela_idx: int
    rela2_idx: int | None = None
    xindex_idx: int | None = None
    xindex2_idx: int | None = None
    shstr_idx: int

    if high_mode:
        # 归一化：(名称, 数据) 或 (名称, 数据, 类型) -> (名称, 数据, 类型)
        norm_high: dict[int, tuple[str, bytes, int]] = {}
        for abs_idx, entry in high_sections.items():
            if len(entry) == 2:
                norm_high[abs_idx] = (entry[0], entry[1], SHT_PROGBITS)
            elif len(entry) == 3:
                norm_high[abs_idx] = (entry[0], entry[1], entry[2])
            else:
                raise ValueError("high_sections 每项必须为 (名称, 数据) 或 (名称, 数据, 类型)")
        high_sections = norm_high

        # 高编号模式：内容节位于调用方指定的绝对索引（>=0xFF00 时进入扩展
        # 编号范围）；元数据节（字符串表/符号表/重定位/扩展索引）固定放在
        # 低端，节名字符串表置于末尾（同为高编号，演练 e_shstrndx 转义）。
        if not any(name == ".text" for name, _d, _t in high_sections.values()):
            raise ValueError("high_sections 必须包含唯一的 .text 节")
        if text_duplicate:
            logical.append({"name": ".text", "type": SHT_PROGBITS, "data": b"\xc3", "align": 16})
        if bss_size is not None:
            logical.append({"name": ".bss", "type": 8, "data": b"", "size_override": bss_size, "align": 16})
        strtab_idx = len(logical)
        logical.append({"name": ".strtab", "type": SHT_STRTAB, "data": b"", "align": 1})
        symtab_idx = len(logical)
        logical.append({"name": ".symtab", "type": SHT_SYMTAB, "data": b"", "align": 8})
        rela_idx = len(logical)
        logical.append({"name": ".rela.text", "type": rela_type, "data": b"", "align": 8})
        if second_rela is not None:
            rela2_idx = len(logical)
            logical.append({"name": ".rela.text.alt", "type": rela_type, "data": b"", "align": 8})
        if need_xindex:
            xindex_idx = len(logical)
            logical.append({"name": ".symtab_shndx", "type": SHT_SYMTAB_SHNDX, "data": b"", "align": 4})
            if xindex_duplicate:
                xindex2_idx = len(logical)
                logical.append(
                    {"name": ".symtab_shndx.alt", "type": SHT_SYMTAB_SHNDX, "data": b"", "align": 4}
                )
        max_index = max(high_sections)
        append_padding(max_index + 1)
        for abs_idx, (sec_name, sec_data, sec_type) in high_sections.items():
            logical[abs_idx] = {
                "name": sec_name,
                "type": sec_type,
                "data": sec_data,
                "align": 16 if sec_name == ".text" else 1,
            }
        text_idx = next(i for i, s in enumerate(logical) if s["name"] == ".text")
        rodata_idx = next((i for i, s in enumerate(logical) if s["name"] == ".rodata"), None)
        shstr_idx = len(logical)
        logical.append({"name": ".shstrtab", "type": SHT_STRTAB, "data": b"", "align": 1})
    else:
        text_idx = append_text_section(text)
        if text_duplicate:
            logical.append({"name": ".text", "type": SHT_PROGBITS, "data": b"\xc3", "align": 16})
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
        if second_rela is not None:
            rela2_idx = len(logical)
            logical.append({"name": ".rela.text.alt", "type": rela_type, "data": b"", "align": 8})
        if need_xindex:
            xindex_idx = len(logical)
            logical.append({"name": ".symtab_shndx", "type": SHT_SYMTAB_SHNDX, "data": b"", "align": 4})
            if xindex_duplicate:
                xindex2_idx = len(logical)
                logical.append(
                    {"name": ".symtab_shndx.alt", "type": SHT_SYMTAB_SHNDX, "data": b"", "align": 4}
                )
        shstr_idx = len(logical)
        logical.append({"name": ".shstrtab", "type": SHT_STRTAB, "data": b"", "align": 1})

    xindex = dict(xindex or {})

    def resolve_shndx(desc: str | int) -> int:
        if isinstance(desc, int):
            return desc
        if desc == "text":
            return text_idx
        if desc == "rodata":
            if rodata_idx is None:
                raise ValueError("文件未包含 .rodata 节")
            return rodata_idx
        raise ValueError(f"未知节描述符：{desc!r}")

    # ---- 字符串表 / 符号表
    str_names = [s[0].encode("latin-1") for s in symbols]
    strtab_blob, str_offsets = _strtab(str_names)
    logical[strtab_idx]["data"] = strtab_blob

    actual_shndx: list[int] = []
    sym_blob = b"\x00" * 24
    for i, (_name, sec_desc, value) in enumerate(symbols):
        info = (STB_GLOBAL << 4) | STT_NOTYPE
        shndx = resolve_shndx(sec_desc)
        actual_shndx.append(shndx)
        sym_one_based = i + 1
        if shndx >= SHN_LORESERVE and sym_one_based not in xindex:
            raise ValueError(
                f"符号 {sym_one_based} 引用高编号节 {shndx}，必须通过 xindex 提供扩展索引"
            )
        encoded_shndx = SHN_XINDEX if sym_one_based in xindex else shndx
        sym_blob += struct.pack("<IBBHQQ", str_offsets[i], info, 0, encoded_shndx, value, 0)
    logical[symtab_idx]["data"] = sym_blob

    # ---- SHT_SYMTAB_SHNDX 内容（与符号表平行，每项 4 字节）
    if xindex_idx is not None:
        entry_count = 1 + len(symbols) + xindex_count_delta
        words = [0] * max(entry_count, 0)
        # 与链接器一致：每项写入对应符号的真实节索引；未走扩展通道的项
        # 复制其 st_shndx。
        for i, real in enumerate(actual_shndx):
            if i + 1 < len(words):
                words[i + 1] = xindex.get(i + 1, real)
        xindex_blob = b"".join(struct.pack("<I", w) for w in words)
        if xindex_bad_size:
            xindex_blob += b"\x00\x00"  # 造成 size % 4 == 2
        logical[xindex_idx]["data"] = xindex_blob
        if xindex2_idx is not None:
            logical[xindex2_idx]["data"] = b"".join(struct.pack("<I", w) for w in words)

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
    if xindex_idx is not None:
        for xi in (xindex_idx, xindex2_idx):
            if xi is None:
                continue
            logical[xi]["link"] = symtab_idx if xindex_link_override is None else xindex_link_override
            logical[xi]["entsize"] = 4

    section_count = len(logical)
    # 节数进入扩展编号范围（>=0xFF00）后，16 位的 e_shnum / e_shstrndx
    # 无法承载，按 gABI 转义：e_shnum=0 时真值在第 0 节头 sh_size；
    # e_shstrndx=0xffff 时真值在第 0 节头 sh_link。
    ext_shnum = section_count >= SHN_LORESERVE
    ext_shstrndx = shstr_idx >= SHN_LORESERVE
    ehdr_shnum = 0 if ext_shnum else section_count
    ehdr_shstrndx = SHN_XINDEX if ext_shstrndx or not shstrndx_valid else shstr_idx
    if not shstrndx_valid:
        ehdr_shstrndx = 0xFFFF

    out = bytearray(shoff + section_count * 64)

    # ELF 头
    ei_ident = bytearray(16)
    ei_ident[0:4] = b"\x7fELF"
    ei_ident[4] = ei_class
    ei_ident[5] = ei_data
    ei_ident[6] = 1
    pack_fmt = ">16sHHIQQQIHHHHHH" if ei_data == 2 else "<16sHHIQQQIHHHHHH"
    ehdr = struct.pack(
        pack_fmt,
        bytes(ei_ident), e_type, e_machine, 1, 0, e_phoff, shoff, 0, 64, 0, 0, 64,
        ehdr_shnum, ehdr_shstrndx,
    )
    out[0:64] = ehdr

    for sec in logical[1:]:
        out[sec["offset"] : sec["offset"] + sec["size"]] = sec["data"]

    # 第 0 节头：常规文件保持全零；扩展编号时承载真实节数 / shstrndx。
    if ext_shnum or ext_shstrndx:
        shdr0 = struct.pack(
            (">IIQQQQIIQQ" if ei_data == 2 else "<IIQQQQIIQQ"),
            0, 0, 0, 0, 0,
            section_count if ext_shnum else 0,
            shstr_idx if ext_shstrndx else 0,
            0, 0, 0,
        )
        out[shoff : shoff + 64] = shdr0

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
