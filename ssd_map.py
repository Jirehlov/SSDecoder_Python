import argparse, importlib, importlib.util, os, struct

hx = lambda x: f"0x{x:08X}"
cl = lambda v, a, b: a if v < a else b if v > b else v

def lm(x):
    if not x:
        return None, "none"
    try:
        if x.endswith(".py") or os.path.sep in x or x.startswith("."):
            p = os.path.abspath(x)
            n = os.path.splitext(os.path.basename(p))[0]
            s = importlib.util.spec_from_file_location(n, p)
            m = importlib.util.module_from_spec(s)
            s.loader.exec_module(m)
            return m, "ok"
        return importlib.import_module(x), "ok"
    except Exception as e:
        return None, f"err:{e}"

def mr(r):
    r = [(a, b) for a, b in r if b > a]
    if not r:
        return []
    r.sort()
    o = [r[0]]
    for a, b in r[1:]:
        pa, pb = o[-1]
        if a <= pb:
            o[-1] = (pa, max(pb, b))
        else:
            o.append((a, b))
    return o

def uu(n, r):
    m = mr((cl(a, 0, n), cl(b, 0, n)) for a, b in r)
    u = sum(b - a for a, b in m)
    un = n - u
    return u, un, (un / n * 100.0 if n else 0.0)

def nf(mod, data, off, sz):
    if not mod or not (hasattr(mod, "xor_decrypt_inplace") and hasattr(mod, "TABLE_DD70") and hasattr(mod, "TABLE_DC70")):
        return None
    if sz < 76:
        return None
    try:
        b = bytearray(data[off:off + 76])
        mod.xor_decrypt_inplace(b, mod.TABLE_DD70, 13, len(b))
        fnl = struct.unpack_from("<19I", b, 0)[18]
        need = 76 + fnl
        if fnl <= 0 or need > sz:
            return None
        b2 = bytearray(data[off:off + need])
        mod.xor_decrypt_inplace(b2, mod.TABLE_DD70, 13, len(b2))
        fn = bytearray(b2[76:need])
        mod.xor_decrypt_inplace(fn, mod.TABLE_DC70, 59, len(fn))
        return fn.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None

def vd(dir_data, total, after):
    if not dir_data or len(dir_data) < 4 or (len(dir_data) % 4):
        return None
    n = len(dir_data) // 4
    if n <= 0 or n > 200000:
        return None
    sizes = struct.unpack_from(f"<{n}I", dir_data, 0)
    if any(s < 1 or s > total for s in sizes):
        return None
    if after + sum(sizes) > total + 16:
        return None
    return sizes

def td(mod, data, off, sz):
    if not mod or not hasattr(mod, "decrypt_and_decompress_resource"):
        return None
    if off < 0 or off + sz > len(data):
        return None
    try:
        _, dd = mod.decrypt_and_decompress_resource(bytearray(data[off:off + sz]), sz)
    except Exception:
        return None
    return vd(dd, len(data), off + sz)

def read_index_list(data, ofs, cnt, total_size):
    if cnt <= 0:
        return []
    need = cnt * 8
    if ofs < 0 or ofs + need > total_size:
        return None
    out = []
    for i in range(cnt):
        o, s = struct.unpack_from("<2i", data, ofs + i * 8)
        out.append((o, s))
    return out

def guess_char_width(pool_len, total_chars):
    if total_chars <= 0:
        return 1
    for w in (2, 1, 4):
        if pool_len == total_chars * w:
            return w
    for w in (2, 1, 4):
        if pool_len % w == 0 and pool_len // w >= total_chars and (pool_len // w - total_chars) < 8:
            return w
    if pool_len % 2 == 0:
        return 2
    return 1

def decode_bytes(b, w):
    if w == 2:
        return b.decode("utf-16-le", errors="replace")
    if w == 4:
        return b.decode("utf-32-le", errors="replace")
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("cp932", errors="replace")

def build_string_table(data, idx_ofs, idx_cnt, pool_ofs, pool_end, total_size):
    idx = read_index_list(data, idx_ofs, idx_cnt, total_size)
    if idx is None:
        return None, None
    pool_ofs = cl(pool_ofs, 0, total_size)
    pool_end = cl(pool_end, 0, total_size)
    if pool_end < pool_ofs:
        pool_end = pool_ofs
    pool = data[pool_ofs:pool_end]
    total_chars = 0
    for o, s in idx:
        if o < 0 or s < 0:
            return None, None
        total_chars = max(total_chars, o + s)
    w = guess_char_width(len(pool), total_chars)
    out = []
    for o, s in idx:
        a = o * w
        b = (o + s) * w
        if a < 0 or b > len(pool) or b < a:
            out.append("")
        else:
            out.append(decode_bytes(pool[a:b], w))
    return out, w

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pck")
    ap.add_argument("--extractor", default="")
    ap.add_argument("--width", type=int, default=120)
    ap.add_argument("--scan", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.pck):
        print("not found")
        return 2

    data = open(args.pck, "rb").read()
    n = len(data)
    if n < 92:
        print("too small")
        return 1

    mod, msg = lm(args.extractor) if args.extractor else (None, "none")

    h = struct.unpack_from("<23i", data, 0)
    header_size = h[0]
    if header_size < 92 or header_size > n:
        header_size = 92

    inc_prop_list_ofs, inc_prop_cnt = h[1], h[2]
    inc_prop_name_index_list_ofs, inc_prop_name_index_cnt = h[3], h[4]
    inc_prop_name_list_ofs, inc_prop_name_cnt = h[5], h[6]
    inc_cmd_list_ofs, inc_cmd_cnt = h[7], h[8]
    inc_cmd_name_index_list_ofs, inc_cmd_name_index_cnt = h[9], h[10]
    inc_cmd_name_list_ofs, inc_cmd_name_cnt = h[11], h[12]
    scn_name_index_list_ofs, scn_name_index_cnt = h[13], h[14]
    scn_name_list_ofs, scn_name_cnt = h[15], h[16]
    scn_data_index_list_ofs, scn_data_index_cnt = h[17], h[18]
    scn_data_list_ofs, scn_data_cnt = h[19], h[20]
    scn_data_exe_angou_mod = h[21]
    original_source_header_size = h[22]

    secs = []
    used = []

    def add(a, b, name, sym, pr):
        a = cl(a, 0, n)
        b = cl(b, 0, n)
        if b > a:
            secs.append((a, b, sym, pr, name))

    def use(a, b):
        a = cl(a, 0, n)
        b = cl(b, 0, n)
        if b > a:
            used.append((a, b))

    def add_fixed(ofs, cnt, elem_sz, name, sym):
        if cnt <= 0:
            return
        a = ofs
        b = ofs + cnt * elem_sz
        add(a, b, name, sym, 80)
        use(a, b)

    add(0, header_size, "pack_header", "H", 100)
    use(0, header_size)

    add_fixed(inc_prop_list_ofs, inc_prop_cnt, 8, "inc_prop_list", "P")
    add_fixed(inc_prop_name_index_list_ofs, inc_prop_name_index_cnt, 8, "inc_prop_name_index_list", "p")

    inc_prop_name_list_end = inc_cmd_list_ofs if inc_cmd_list_ofs > inc_prop_name_list_ofs else n
    if inc_prop_name_list_ofs >= 0 and inc_prop_name_list_end > inc_prop_name_list_ofs:
        add(inc_prop_name_list_ofs, inc_prop_name_list_end, "inc_prop_name_list", "s", 55)
        use(inc_prop_name_list_ofs, inc_prop_name_list_end)

    add_fixed(inc_cmd_list_ofs, inc_cmd_cnt, 8, "inc_cmd_list", "C")
    add_fixed(inc_cmd_name_index_list_ofs, inc_cmd_name_index_cnt, 8, "inc_cmd_name_index_list", "c")

    inc_cmd_name_list_end = scn_name_index_list_ofs if scn_name_index_list_ofs > inc_cmd_name_list_ofs else n
    if inc_cmd_name_list_ofs >= 0 and inc_cmd_name_list_end > inc_cmd_name_list_ofs:
        add(inc_cmd_name_list_ofs, inc_cmd_name_list_end, "inc_cmd_name_list", "n", 55)
        use(inc_cmd_name_list_ofs, inc_cmd_name_list_end)

    add_fixed(scn_name_index_list_ofs, scn_name_index_cnt, 8, "scn_name_index_list", "N")

    scn_name_list_end = scn_data_index_list_ofs if scn_data_index_list_ofs > scn_name_list_ofs else scn_name_list_ofs
    if scn_name_list_ofs >= 0 and scn_name_list_end > scn_name_list_ofs:
        add(scn_name_list_ofs, scn_name_list_end, "scn_name_list", "S", 55)
        use(scn_name_list_ofs, scn_name_list_end)

    add_fixed(scn_data_index_list_ofs, scn_data_index_cnt, 8, "scn_data_index_list", "I")

    scn_data_idx = read_index_list(data, scn_data_index_list_ofs, scn_data_index_cnt, n) or []
    scn_data_total = 0
    for o, s in scn_data_idx:
        if o >= 0 and s >= 0:
            scn_data_total = max(scn_data_total, o + s)

    scn_data_a = scn_data_list_ofs
    scn_data_b = scn_data_list_ofs + scn_data_total
    if scn_data_total > 0 and scn_data_b > scn_data_a:
        add(scn_data_a, scn_data_b, "scn_data_list", "L", 70)
        use(scn_data_a, scn_data_b)

    scn_names, scn_name_w = build_string_table(
        data,
        scn_name_index_list_ofs,
        scn_name_index_cnt,
        scn_name_list_ofs,
        scn_name_list_end,
        n,
    )
    if scn_names is None:
        scn_names = []
        scn_name_w = None

    item_cnt = min(len(scn_data_idx), len(scn_names)) if scn_names else len(scn_data_idx)
    for i in range(item_cnt):
        o, s = scn_data_idx[i]
        if o < 0 or s <= 0:
            continue
        a = scn_data_list_ofs + o
        b = a + s
        nm = scn_names[i] if i < len(scn_names) else f"scene#{i}"
        if args.width and len(nm) > args.width:
            nm = nm[: max(0, args.width - 1)] + "…"
        add(a, b, nm, "F", 40)
        use(a, b)

    os_dir_off = scn_data_b
    os_dir_sz = original_source_header_size if original_source_header_size and original_source_header_size > 0 else 0
    sizes = None
    how = "none"

    if os_dir_sz > 0 and 0 <= os_dir_off <= n - os_dir_sz:
        add(os_dir_off, os_dir_off + os_dir_sz, "original_source_size_list_data", "D", 75)
        use(os_dir_off, os_dir_off + os_dir_sz)
        sizes = td(mod, data, os_dir_off, os_dir_sz)
        how = "header" if sizes else how
        if sizes is None:
            sizes = vd(data[os_dir_off:os_dir_off + os_dir_sz], n, os_dir_off + os_dir_sz)
            how = "plain" if sizes else how

    if sizes is None and args.scan and os_dir_sz > 0 and mod and hasattr(mod, "decrypt_and_decompress_resource"):
        scan_a = cl(scn_data_b, 0, n)
        scan_b = cl(n - os_dir_sz, 0, n)
        for off in range(scan_a, scan_b + 1, 4):
            s = td(mod, data, off, os_dir_sz)
            if s is not None:
                os_dir_off = off
                sizes = s
                how = "scan"
                secs = [x for x in secs if not (x[2] == "D" and x[4] == "original_source_size_list_data")]
                add(os_dir_off, os_dir_off + os_dir_sz, "original_source_size_list_data", "D", 75)
                use(os_dir_off, os_dir_off + os_dir_sz)
                break

    tail_start = scn_data_b
    if os_dir_sz > 0 and sizes:
        off = os_dir_off + os_dir_sz
        last = off
        for i, sz in enumerate(sizes):
            a, b = off, off + sz
            if a >= n:
                break
            b = min(b, n)
            name = nf(mod, data, a, b - a) or f"original_source#{i}"
            if args.width and len(name) > args.width:
                name = name[: max(0, args.width - 1)] + "…"
            add(a, b, name, "O", 45)
            use(a, b)
            off += sz
            last = b
            if off > n:
                break
        tail_start = max(tail_start, last)
        if tail_start < n:
            add(tail_start, n, f"tail/extra (os:{how})", "T", 10)
            use(tail_start, n)
    else:
        if os_dir_sz > 0 and 0 <= os_dir_off <= n:
            tail_start = max(tail_start, os_dir_off + os_dir_sz)
        if tail_start < n:
            nm = "tail/extra"
            if os_dir_sz > 0:
                nm = f"original_source_data (unpartitioned, osz={os_dir_sz})"
                if how != "none":
                    nm += f" ({how})"
            add(tail_start, n, nm, "T", 10)
            use(tail_start, n)

    u, un, r = uu(n, used)
    gaps = []
    m_used = mr((cl(a, 0, n), cl(b, 0, n)) for a, b in used)
    prev = 0
    for a, b in m_used:
        if a > prev:
            gaps.append((prev, a))
        prev = max(prev, b)
    if prev < n:
        gaps.append((prev, n))
    for a, b in gaps:
        if b > a:
            secs.append((a, b, "G", 1, "gap/unknown"))

    print("==== PCK Section Map ====")
    print(f"file: {args.pck}")
    print(f"size: {n} bytes ({hx(n)})")
    print(f"extractor: {args.extractor or '(none)'}  load: {msg}  has_decrypt: {bool(mod and hasattr(mod,'decrypt_and_decompress_resource'))}")
    print(f"header_size={header_size} scn_data_exe_angou_mod={scn_data_exe_angou_mod} original_source_header_size={original_source_header_size}")
    print(f"counts: inc_prop={inc_prop_cnt} inc_cmd={inc_cmd_cnt} scn_name={scn_name_cnt} scn_data_index={scn_data_index_cnt} scn_data_cnt={scn_data_cnt}")
    print(f"scn_name_char_width={scn_name_w if scn_name_w is not None else 'unknown'}")
    if os_dir_sz > 0:
        print(f"original_source_partition: dir_off={hx(os_dir_off)} dir_size={os_dir_sz} entries={len(sizes) if sizes else 0} via {how}")
    print(f"unused(by ranges): {un} bytes ({r:.2f}%)\n")

    print("==== SYM Legend ====")
    print("H : pack_header")
    print("P : inc_prop_list")
    print("p : inc_prop_name_index_list")
    print("s : inc_prop_name_list")
    print("C : inc_cmd_list")
    print("c : inc_cmd_name_index_list")
    print("n : inc_cmd_name_list")
    print("N : scn_name_index_list")
    print("S : scn_name_list")
    print("I : scn_data_index_list")
    print("L : scn_data_list (aggregate)")
    print("F : scene_data item (per index)")
    print("D : original_source_size_list_data")
    print("O : original_source_data item (partitioned)")
    print("T : tail/extra")
    print("G : gap/unknown\n")

    print("==== Sections (ranges) ====")
    print("SYM  START       LAST        SIZE        NAME")
    print("---- ----------  ----------  ----------  ----")
    for a, b, sym, pr, name in sorted(secs, key=lambda x: (x[0], x[1], -x[3], x[2], x[4])):
        if b <= a:
            continue
        print(f"{sym:>3}  {hx(a)}  {hx(b-1)}  {b-a:10d}  {name}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
