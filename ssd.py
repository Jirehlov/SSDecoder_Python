import argparse
import os
import re
import struct
from datetime import datetime

TABLE_DC70 = bytes([
    0x28, 0x2D, 0x91, 0x73, 0xF5, 0x06, 0xD6, 0xBA, 0xBF, 0xF3, 0x45, 0x3F, 0xF1, 0x61, 0xB1, 0xE9,
    0xE1, 0x98, 0x3D, 0x6F, 0x31, 0x0D, 0xAC, 0xB1, 0x08, 0x83, 0x9D, 0x0D, 0x10, 0xD1, 0x41, 0xF9,
    0x00, 0xBA, 0x1A, 0xCF, 0x13, 0x71, 0xE4, 0x86, 0x21, 0x2F, 0x22, 0xAA, 0xDD, 0x4C, 0x7F, 0x9B,
    0x1F, 0x9A, 0xD5, 0x49, 0xE9, 0x34, 0x89, 0x56, 0xA7, 0x96, 0x1B, 0x52, 0x67, 0x6A, 0x6F, 0x74,
    0xCD, 0x80, 0x45, 0xF3, 0xE7, 0x2A, 0x1D, 0x16, 0xB2, 0xF1, 0x54, 0xC8, 0x6C, 0x2B, 0x0D, 0xD4,
    0x65, 0xF7, 0xE3, 0x36, 0xD4, 0xA5, 0x3B, 0xD1, 0x79, 0x4C, 0x54, 0xF0, 0x2A, 0xB4, 0xB2, 0x56,
    0x45, 0x2E, 0xAB, 0x23, 0x65, 0xC3, 0x45, 0xA0, 0xC3, 0x92, 0x48, 0x9D, 0xEA, 0xDD, 0x31, 0x2C,
    0xE9, 0xE2, 0x10, 0x7B, 0x88, 0xC5, 0xFA, 0x74, 0xAD, 0x03, 0xB8, 0x9E, 0xD5, 0xF5, 0x6F, 0xDC,
    0xFA, 0x44, 0x49, 0x31, 0xF6, 0x83, 0x32, 0xFF, 0xC2, 0xB1, 0xE9, 0xE1, 0x98, 0x3D, 0x6F, 0x31,
    0x0D, 0xAC, 0xB1, 0x08, 0x83, 0x9D, 0x0D, 0x10, 0xD1, 0x41, 0xF9, 0x00, 0xBA, 0x1A, 0xCF, 0x13,
    0x71, 0xE4, 0x86, 0x21, 0x2F, 0x22, 0xAA, 0x6A, 0x35, 0xB1, 0x7E, 0xD1, 0xB5, 0xE7, 0xEC, 0x7A,
    0x6F, 0x26, 0x74, 0x0E, 0xDB, 0x27, 0x4C, 0xA5, 0xF1, 0x0E, 0x2D, 0x70, 0xC4, 0x40, 0x5D, 0x4F,
    0xDA, 0x9E, 0xC5, 0x49, 0x7B, 0xBD, 0xE8, 0xDF, 0xD8, 0x29, 0xB9, 0x16, 0x3D, 0x1A, 0xBA, 0xBF,
    0xDF, 0xD8, 0x29, 0xB9, 0x16, 0x3D, 0x1A, 0x76, 0xD0, 0x87, 0x9B, 0x2D, 0x0C, 0x7B, 0xD1, 0xE1,
    0xAD, 0xEE, 0xCA, 0xF4, 0x92, 0xDE, 0xE4, 0x76, 0x10, 0xDD, 0x2A, 0x52, 0xDC, 0x73, 0x4E, 0x54,
    0x8C, 0x30, 0x3D, 0x9A, 0xB2, 0x9B, 0xB8, 0x93, 0x29, 0x55, 0xFA, 0x7A, 0xC9, 0xDA, 0x10, 0x97,
])

TABLE_DD70 = bytes([
    0x0E, 0xDB, 0x27, 0x4C, 0xA5, 0xF1, 0x0E, 0x2D, 0x70, 0xC4, 0x40, 0x5D, 0x4F, 0xDA, 0xA0, 0xC3,
    0x92, 0x48, 0x9D, 0xEA, 0xDD, 0x31, 0x2C, 0xE9, 0xE2, 0x10, 0x22, 0xAA, 0xD8, 0x29, 0xB9, 0x16,
    0x3D, 0x1A, 0x76, 0xD0, 0x87, 0x9B, 0x2D, 0x0C, 0x7B, 0xD1, 0xE1, 0xAD, 0x9E, 0xC5, 0x49, 0x7B,
    0xBD, 0xE8, 0xDF, 0xEE, 0xCA, 0xF4, 0x92, 0xDE, 0xE4, 0x76, 0x10, 0xDD, 0x2A, 0x52, 0xDC, 0x73,
    0x4E, 0x54, 0x8C, 0x30, 0x3D, 0x9A, 0xB2, 0x9B, 0xB8, 0x93, 0x29, 0x55, 0xFA, 0x7A, 0xC9, 0xDA,
    0x10, 0x97, 0xE5, 0xB6, 0x23, 0x02, 0xDD, 0x38, 0x4C, 0x2C, 0xC4, 0x2D, 0x7F, 0x9B, 0x1F, 0x9A,
    0xD5, 0x49, 0xE9, 0x34, 0x89, 0x56, 0xA7, 0x96, 0x14, 0xBE, 0x2E, 0xC5, 0xB1, 0x7E, 0xD1, 0xB5,
    0xE7, 0xE6, 0xD5, 0xF5, 0x06, 0xD6, 0xBA, 0xBF, 0xF3, 0x45, 0x3F, 0xF1, 0x61, 0xDD, 0x54, 0xC8,
    0x2E, 0xAB, 0x7B, 0x88, 0xC5, 0xFA, 0x74, 0xAD, 0x03, 0xB8, 0x9E, 0xD5, 0xF5, 0x6F, 0x6C, 0x2B,
    0x0D, 0xD4, 0x65, 0xF7, 0xE3, 0x36, 0xD4, 0xA5, 0x3B, 0xD1, 0x79, 0x4C, 0x54, 0xF0, 0x2A, 0xB4,
    0xB2, 0x56, 0x45, 0xDC, 0xFA, 0x44, 0x49, 0x31, 0xF6, 0x83, 0x32, 0xFF, 0xC2, 0xB1, 0xE9, 0xE1,
    0x98, 0x3D, 0x6F, 0x31, 0x0D, 0xAC, 0xB1, 0x08, 0x83, 0x9D, 0x0D, 0x10, 0xD1, 0x41, 0xF9, 0x00,
    0xBA, 0x1A, 0xCF, 0x13, 0x71, 0xE4, 0x86, 0x21, 0x2F, 0x23, 0x65, 0xC3, 0x45, 0xA0, 0x1B, 0x52,
    0x67, 0x6A, 0x6F, 0x74, 0xEC, 0x7A, 0x6F, 0x26, 0x74, 0x0E, 0xDB, 0x27, 0x4C, 0xA5, 0xF1, 0x0E,
    0x2D, 0x70, 0xC4, 0x40, 0x5D, 0x4F, 0xDA, 0x9E, 0xC5, 0x49, 0x7B, 0xBD, 0xE8, 0xDF, 0xD8, 0x29,
    0xB9, 0x16, 0x3D, 0x1A, 0x76, 0xD0, 0x87, 0x9B, 0x2D, 0x0C, 0x7B, 0xD1, 0xE1, 0xAD, 0xEE, 0xCA,
])

TABLE_DE70 = bytes([
    0x6A, 0x35, 0xB1, 0x7E, 0xD1, 0xB5, 0xE7, 0xE6, 0xD5, 0xA9, 0x19, 0x0F, 0x28, 0x2D, 0xF4, 0xC3,
    0x92, 0x48, 0x9D, 0xEA, 0xDD, 0x31, 0x2C, 0xE9, 0xE2, 0x10, 0x91, 0x73, 0x4C, 0x3E, 0x08, 0x5F,
    0x47, 0xA9, 0xDF, 0x88, 0x9F, 0xD4, 0xCC, 0x69, 0x1F, 0x30, 0x9F, 0xE7, 0xCD, 0x80, 0x45, 0xF3,
    0xE7, 0x2A, 0x1D, 0x16, 0xB2, 0xF1, 0x6A, 0x35, 0x67, 0x6A, 0x6F, 0x74, 0xEC, 0x7A, 0x6F, 0x26,
    0x74, 0x92, 0xDE, 0xE4, 0x76, 0x10, 0xDD, 0x2A, 0x52, 0xDC, 0x73, 0x4E, 0x54, 0x8C, 0x30, 0x3D,
    0x9A, 0xB2, 0x9B, 0xB8, 0x93, 0x29, 0x55, 0xFA, 0x7A, 0xC9, 0xDA, 0x10, 0x97, 0xE5, 0xB6, 0x23,
    0x02, 0xDD, 0x38, 0x4C, 0x2C, 0xC4, 0x2D, 0x39, 0x5C, 0x36, 0x22, 0x9F, 0x91, 0x73, 0xF5, 0x06,
    0xD6, 0xBA, 0xBF, 0xF3, 0x45, 0x3F, 0xF1, 0x61, 0xDD, 0x4C, 0x7F, 0x9B, 0x1F, 0x9A, 0xD5, 0x49,
    0xE9, 0x34, 0x89, 0x56, 0xA7, 0x96, 0x14, 0xBE, 0x2E, 0xC5, 0x3E, 0x08, 0x5F, 0x47, 0xA9, 0xDF,
    0x88, 0x9F, 0xD4, 0xCC, 0x69, 0x1F, 0x30, 0x9F, 0xE7, 0xCD, 0x80, 0x45, 0xF3, 0xE7, 0x2A, 0x1D,
    0x16, 0xB2, 0xF1, 0x54, 0xC8, 0x6C, 0x2B, 0x0D, 0xD4, 0x65, 0xF7, 0xE3, 0x36, 0xD4, 0xA5, 0x3B,
    0xD1, 0x79, 0x4C, 0x54, 0xF0, 0x2A, 0xB4, 0xB2, 0x56, 0x45, 0x2E, 0xCA, 0xF4, 0x92, 0xDE, 0xE4,
    0x76, 0x10, 0xDD, 0x2A, 0x52, 0xDC, 0x73, 0x4E, 0x54, 0x8C, 0x30, 0x3D, 0x9A, 0xB2, 0x9B, 0xB8,
    0x93, 0x29, 0x55, 0xFA, 0x7A, 0xC9, 0xDA, 0x10, 0x97, 0xAB, 0x23, 0x65, 0xC3, 0x45, 0xA0, 0xC3,
    0x92, 0x48, 0x9D, 0xEA, 0xDD, 0x31, 0x2C, 0xE9, 0xE2, 0x10, 0x7B, 0x88, 0xC5, 0xFA, 0x74, 0xAD,
    0x03, 0xB8, 0x9E, 0xD5, 0xF5, 0x6F, 0xDC, 0xFA, 0x44, 0x49, 0x31, 0xF6, 0x83, 0x32, 0xFF, 0xC2,
])

TABLE_DF70 = bytes([
    0xA9, 0x19, 0x0F, 0x28, 0x2D, 0x1B, 0x52, 0x39, 0x5C, 0x36, 0x22, 0x9F, 0x91, 0x73, 0x6A, 0x35,
    0x67, 0x6A, 0x6F, 0x74, 0xEC, 0x7A, 0x6F, 0x26, 0x74, 0x0E, 0xDB, 0x27, 0x4C, 0xA5, 0xF1, 0x0E,
    0x2D, 0x70, 0xC4, 0x40, 0x5D, 0x4F, 0xDA, 0x9E, 0xC5, 0x49, 0x7B, 0xBD, 0xE8, 0xDF, 0xEE, 0xCA,
    0xF4, 0x92, 0xDE, 0xE4, 0x76, 0x10, 0xDD, 0x2A, 0x52, 0xDC, 0x73, 0x4E, 0x54, 0x8C, 0x30, 0x3D,
    0x9A, 0xB2, 0x9B, 0xB8, 0x93, 0x29, 0x55, 0xFA, 0x7A, 0xC9, 0xDA, 0x10, 0x97, 0xE5, 0xB6, 0x23,
    0x02, 0xDD, 0x38, 0x4C, 0x2C, 0xC4, 0x2D, 0x7F, 0x9B, 0x1F, 0x9A, 0xD5, 0x49, 0xE9, 0x34, 0x89,
    0x56, 0xA7, 0x96, 0x14, 0xBE, 0x2E, 0xC5, 0xB1, 0x7E, 0xD1, 0xB5, 0xE7, 0xE6, 0xD5, 0xF5, 0x06,
    0xD6, 0xBA, 0xBF, 0xF3, 0x45, 0x3F, 0xF1, 0x61, 0xDD, 0x4C, 0x3E, 0x08, 0x5F, 0x47, 0xA9, 0xDF,
    0x88, 0x9F, 0xD4, 0xCC, 0x69, 0x1F, 0x30, 0x9F, 0xE7, 0xCD, 0x80, 0x45, 0xF3, 0xE7, 0x2A, 0x1D,
    0x16, 0xB2, 0xF1, 0x54, 0xC8, 0x6C, 0x2B, 0x0D, 0xD4, 0x65, 0xF7, 0xE3, 0x36, 0xD4, 0xA5, 0x3B,
    0xD1, 0x79, 0x4C, 0x54, 0xF0, 0x2A, 0xB4, 0xB2, 0x56, 0x45, 0x2E, 0xAB, 0x7B, 0x88, 0xC5, 0xFA,
    0x74, 0xAD, 0x03, 0xB8, 0x9E, 0xD5, 0xF5, 0x6F, 0xDC, 0xFA, 0x44, 0x22, 0xAA, 0xD8, 0x29, 0xB9,
    0x16, 0x3D, 0x1A, 0x76, 0xD0, 0x87, 0x9B, 0x2D, 0x0C, 0x7B, 0xD1, 0xE1, 0xAD, 0xA9, 0x19, 0x0F,
    0x28, 0x2D, 0x1B, 0x52, 0x39, 0x5C, 0x36, 0x22, 0x9F, 0x49, 0x31, 0xF6, 0x83, 0x32, 0xFF, 0xC2,
    0xB1, 0xE9, 0xE1, 0x98, 0x3D, 0x6F, 0x31, 0x0D, 0xAC, 0xB1, 0x08, 0x83, 0x9D, 0x0D, 0x10, 0xD1,
    0x41, 0xF9, 0x00, 0xBA, 0x1A, 0xCF, 0x13, 0x71, 0xE4, 0x86, 0x21, 0x2F, 0x23, 0x65, 0xC3, 0x45,
])

hx = lambda x: f"0x{x:08X}"
cl = lambda v, a, b: a if v < a else b if v > b else v

NAME_W = 50
MAX_DECOMP = 512 * 1024 * 1024

def _tables_ok():
    for t in (TABLE_DC70, TABLE_DD70, TABLE_DE70, TABLE_DF70):
        if not isinstance(t, (bytes, bytearray)) or len(t) != 256:
            return False
    return True

def xor_decrypt_inplace(data: bytearray, table: bytes, start_index: int, length: int) -> None:
    idx = start_index
    for i in range(length):
        data[i] ^= table[idx]
        idx = (idx + 1) % 256

def lzss_decompress_limited(src: bytes, max_out: int) -> bytes:
    if not src or len(src) < 8:
        return b""
    decompressed_size = struct.unpack_from("<I", src, 4)[0]
    if decompressed_size == 0:
        return b""
    if decompressed_size > max_out:
        raise ValueError("decompressed_size too large")
    output = bytearray(decompressed_size)
    src_pos = 8
    dst_pos = 0
    while dst_pos < decompressed_size:
        if src_pos >= len(src):
            break
        flags = src[src_pos]
        src_pos += 1
        for _ in range(8):
            if dst_pos >= decompressed_size:
                break
            if flags & 1:
                if src_pos >= len(src):
                    break
                output[dst_pos] = src[src_pos]
                src_pos += 1
                dst_pos += 1
            else:
                if src_pos + 2 > len(src):
                    break
                word = struct.unpack_from("<H", src, src_pos)[0]
                src_pos += 2
                length = (word & 0xF) + 2
                offset = word >> 4
                if offset <= 0:
                    break
                for _ in range(length):
                    if dst_pos >= decompressed_size:
                        break
                    if dst_pos - offset < 0:
                        break
                    output[dst_pos] = output[dst_pos - offset]
                    dst_pos += 1
            flags >>= 1
    return bytes(output)

def blit_with_wrapping_mask(dst: bytearray, src: bytes, block_width: int, block_height: int, mask: bytes, mask_width: int, mask_height: int, use_less_than: bool) -> None:
    if not src or not dst:
        return
    mask_total = mask_width * mask_height
    start_row = (mask_height - 37 % mask_height) % mask_height
    start_col = (mask_width - 111 % mask_width) % mask_width
    row_offset = start_row * mask_width
    src_idx = 0
    dst_idx = 0
    for _ in range(block_height):
        col = start_col
        for _ in range(block_width):
            mask_idx = row_offset + col
            mask_val = mask[mask_idx]
            if use_less_than:
                if mask_val < 0x80:
                    dst[dst_idx * 4 : (dst_idx + 1) * 4] = src[src_idx * 4 : (src_idx + 1) * 4]
            else:
                if mask_val >= 0x80:
                    dst[dst_idx * 4 : (dst_idx + 1) * 4] = src[src_idx * 4 : (src_idx + 1) * 4]
            src_idx += 1
            dst_idx += 1
            col += 1
            if col >= mask_width:
                col = 0
        row_offset += mask_width
        if row_offset >= mask_total:
            row_offset = 0

def decrypt_and_decompress_resource_safe(block: bytearray):
    if not _tables_ok():
        raise RuntimeError("tables missing")
    bs = len(block)
    if bs < 76:
        raise ValueError("too small")
    xor_decrypt_inplace(block, TABLE_DD70, 13, bs)
    header = struct.unpack_from("<19I", block, 0)
    param6 = header[6]
    param9 = header[9]
    param10 = header[10]
    compressed_size = header[17]
    filename_len = header[18]
    if filename_len > bs - 76:
        raise ValueError("bad filename_len")
    if compressed_size <= 0:
        raise ValueError("bad compressed_size")
    filename_start = 19 * 4
    if filename_start + filename_len > bs:
        raise ValueError("bad filename range")
    mask_width = param6 % 16 + 16
    mask_height = param9 % 16 + 16
    block_width = param10 % 32 + 32
    half_size = (compressed_size + 1) // 2
    num_dwords = (half_size + 3) // 4
    block_height = (block_width + num_dwords - 1) // block_width
    total_size = 4 * block_width * block_height
    data_start = 76 + filename_len
    if data_start + 2 * total_size > bs:
        raise ValueError("not enough data")
    if compressed_size > 2 * total_size:
        raise ValueError("compressed_size too large")
    filename_data = bytearray(block[filename_start : filename_start + filename_len])
    xor_decrypt_inplace(filename_data, TABLE_DC70, 59, filename_len)
    filename = filename_data.decode("utf-16-le", errors="replace").rstrip("\x00")
    mask_size = mask_width * mask_height
    mask = bytearray(mask_size)
    idx_96 = 96
    idx_11 = 11
    for i in range(mask_size):
        header_idx = (idx_11 + 1)
        val = (header[header_idx] & 0xFF) if header_idx < 19 else 0
        mask[i] = TABLE_DE70[idx_96] ^ val
        idx_96 = (idx_96 + 1) % 256
        idx_11 = (idx_11 + 1) % 16
    buf1 = bytearray(total_size)
    buf2 = bytearray(total_size)
    src1 = bytes(block[data_start : data_start + total_size])
    src2 = bytes(block[data_start + total_size : data_start + 2 * total_size])
    blit_with_wrapping_mask(buf1, src1, block_width, block_height, mask, mask_width, mask_height, False)
    blit_with_wrapping_mask(buf1, src2, block_width, block_height, mask, mask_width, mask_height, True)
    blit_with_wrapping_mask(buf2, src1, block_width, block_height, mask, mask_width, mask_height, True)
    blit_with_wrapping_mask(buf2, src2, block_width, block_height, mask, mask_width, mask_height, False)
    combined = bytearray(compressed_size)
    combined[:half_size] = buf1[:half_size]
    combined[half_size:compressed_size] = buf2[: compressed_size - half_size]
    xor_decrypt_inplace(combined, TABLE_DF70, 173, compressed_size)
    result = lzss_decompress_limited(bytes(combined), MAX_DECOMP)
    return filename, result

def mr(ranges):
    r = [(a, b) for a, b in ranges if b > a]
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

def uu(n, ranges):
    m = mr((cl(a, 0, n), cl(b, 0, n)) for a, b in ranges)
    u = sum(b - a for a, b in m)
    un = n - u
    return u, un, (un / n * 100.0 if n else 0.0)

def read_index_list(data: bytes, ofs: int, cnt: int, total_size: int):
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

def guess_char_width(pool_len: int, total_chars: int) -> int:
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

def decode_bytes(b: bytes, w: int) -> str:
    if w == 2:
        return b.decode("utf-16-le", errors="replace")
    if w == 4:
        return b.decode("utf-32-le", errors="replace")
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("cp932", errors="replace")

def build_string_table(data: bytes, idx_ofs: int, idx_cnt: int, pool_ofs: int, pool_end: int, total_size: int):
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

def vd(dir_data: bytes, total: int, after: int):
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

def td(data: bytes, off: int, sz: int):
    if off < 0 or off + sz > len(data):
        return None
    if not _tables_ok():
        return None
    try:
        _, dd = decrypt_and_decompress_resource_safe(bytearray(data[off:off + sz]))
    except Exception:
        return None
    return vd(dd, len(data), off + sz)

def nf(data: bytes, off: int, sz: int):
    if not _tables_ok():
        return None
    if sz < 76:
        return None
    try:
        b = bytearray(data[off:off + 76])
        xor_decrypt_inplace(b, TABLE_DD70, 13, len(b))
        fnl = struct.unpack_from("<19I", b, 0)[18]
        need = 76 + fnl
        if fnl <= 0 or need > sz:
            return None
        b2 = bytearray(data[off:off + need])
        xor_decrypt_inplace(b2, TABLE_DD70, 13, len(b2))
        fn = bytearray(b2[76:need])
        xor_decrypt_inplace(fn, TABLE_DC70, 59, len(fn))
        return fn.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None

def _sanitize_seg(seg: str, max_len: int = 120) -> str:
    seg = seg.strip()
    seg = re.sub(r"[\x00-\x1f\x7f]+", "_", seg)
    seg = re.sub(r'[<>:"|?*]+', "_", seg)
    seg = seg.rstrip(" .")
    if not seg:
        seg = "noname"
    if len(seg) > max_len:
        seg = seg[:max_len]
    return seg

def _name_to_relpath(name: str) -> str:
    s = (name or "").replace("\\", "/")
    parts = []
    for seg in s.split("/"):
        if seg in ("", ".", ".."):
            continue
        parts.append(_sanitize_seg(seg))
    if not parts:
        return "noname"
    return "/".join(parts)

def _safe_join(base_dir: str, rel: str) -> str:
    base_dir = os.path.abspath(base_dir)
    rel = _name_to_relpath(rel)
    out = os.path.abspath(os.path.join(base_dir, rel))
    if out != base_dir and not out.startswith(base_dir + os.sep):
        raise ValueError("unsafe path traversal detected")
    return out

def _dn(name: str) -> str:
    if len(name) <= NAME_W:
        return name
    if NAME_W <= 1:
        return "…"
    return name[: NAME_W - 1] + "…"

def build_sections(data: bytes):
    n = len(data)
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
        a2 = cl(a, 0, n)
        b2 = cl(b, 0, n)
        if b2 > a2:
            secs.append([a2, b2, sym, pr, name, False])

    def use(a, b):
        a2 = cl(a, 0, n)
        b2 = cl(b, 0, n)
        if b2 > a2:
            used.append((a2, b2))

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
        add(a, b, nm, "F", 40)
        use(a, b)

    os_dir_off = scn_data_b
    os_dir_sz = original_source_header_size if original_source_header_size and original_source_header_size > 0 else 0
    sizes = None
    how = "none"

    if os_dir_sz > 0 and 0 <= os_dir_off <= n - os_dir_sz:
        add(os_dir_off, os_dir_off + os_dir_sz, "original_source_size_list_data", "D", 75)
        use(os_dir_off, os_dir_off + os_dir_sz)
        sizes = td(data, os_dir_off, os_dir_sz)
        how = "header" if sizes else how
        if sizes is None:
            sizes = vd(data[os_dir_off:os_dir_off + os_dir_sz], n, os_dir_off + os_dir_sz)
            how = "plain" if sizes else how

    tail_start = scn_data_b
    if os_dir_sz > 0 and sizes:
        off = os_dir_off + os_dir_sz
        last = off
        for i, sz in enumerate(sizes):
            a, b = off, off + sz
            if a >= n:
                break
            b = min(b, n)
            nm = nf(data, a, b - a) or f"original_source#{i}"
            add(a, b, nm, "O", 45)
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

    _, un, r = uu(n, used)
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
            secs.append([a, b, "G", 1, "gap/unknown", False])

    secs_sorted = sorted(secs, key=lambda x: (x[0], x[1], -x[3], x[2], x[4]))
    meta = {
        "header_size": header_size,
        "scn_data_exe_angou_mod": scn_data_exe_angou_mod,
        "original_source_header_size": original_source_header_size,
        "inc_prop_cnt": inc_prop_cnt,
        "inc_cmd_cnt": inc_cmd_cnt,
        "scn_name_cnt": scn_name_cnt,
        "scn_data_index_cnt": scn_data_index_cnt,
        "scn_data_cnt": scn_data_cnt,
        "scn_name_w": scn_name_w,
        "os_dir_off": os_dir_off,
        "os_dir_sz": os_dir_sz,
        "os_entries": len(sizes) if sizes else 0,
        "os_how": how,
        "unused_bytes": un,
        "unused_pct": r,
    }
    return secs_sorted, meta

def dump_all_sections(pck_path: str, out_dir: str) -> int:
    if not os.path.exists(pck_path):
        print("not found")
        return 2
    data = open(pck_path, "rb").read()
    n = len(data)
    if n < 92:
        print("too small")
        return 1

    dt = datetime.now()
    subdir_name = f"ss_{dt.strftime('%Y%m%d_%H%M%S')}"
    base_out = os.path.join(out_dir, subdir_name)
    os.makedirs(base_out, exist_ok=True)

    secs, meta = build_sections(data)

    dumped = 0
    for row in secs:
        a, b, sym, pr, name, ex = row
        if b <= a:
            row[5] = False
            continue
        try:
            out_path = _safe_join(base_out, name)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(data[a:b])
            row[5] = True
            dumped += 1
        except Exception:
            row[5] = False

    print("==== PCK Section Map ====")
    print(f"file: {pck_path}")
    print(f"size: {n} bytes ({hx(n)})")
    print("header:")
    print(f"  header_size={meta['header_size']}")
    print(f"  scn_data_exe_angou_mod={meta['scn_data_exe_angou_mod']}")
    print(f"  original_source_header_size={meta['original_source_header_size']}")
    print("counts:")
    print(f"  inc_prop={meta['inc_prop_cnt']}  inc_cmd={meta['inc_cmd_cnt']}")
    print(f"  scn_name={meta['scn_name_cnt']}  scn_data_index={meta['scn_data_index_cnt']}  scn_data_cnt={meta['scn_data_cnt']}")
    print(f"scn_name_char_width={meta['scn_name_w'] if meta['scn_name_w'] is not None else 'unknown'}")
    if meta["os_dir_sz"] > 0:
        print(f"original_source_partition: dir_off={hx(meta['os_dir_off'])} dir_size={meta['os_dir_sz']} entries={meta['os_entries']} via {meta['os_how']}")
    print(f"unused(by ranges): {meta['unused_bytes']} bytes ({meta['unused_pct']:.2f}%)")
    print(f"dumped: {dumped}/{len([x for x in secs if x[1] > x[0]])} -> {base_out}")
    print()

    print("==== Sections (ranges) ====")
    print(f"{'SYM':>3}  {'START':<10}  {'LAST':<10}  {'SIZE':>10}  {'EXTRACTED':<9}  {'NAME':<{NAME_W}}")
    print(f"{'-'*3}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*9}  {'-'*NAME_W}")
    for a, b, sym, pr, name, ex in secs:
        if b <= a:
            continue
        print(f"{sym:>3}  {hx(a):<10}  {hx(b-1):<10}  {b-a:10d}  {str(bool(ex)):<9}  {_dn(name):<{NAME_W}}")

    return 0

def compare_pcks(p1: str, p2: str) -> int:
    if not os.path.exists(p1) or not os.path.exists(p2):
        print("not found")
        return 2
    d1 = open(p1, "rb").read()
    d2 = open(p2, "rb").read()
    if len(d1) < 92 or len(d2) < 92:
        print("too small")
        return 1

    s1, _ = build_sections(d1)
    s2, _ = build_sections(d2)

    def group(secs):
        m = {}
        for a, b, sym, pr, name, ex in secs:
            k = (sym, name)
            m.setdefault(k, []).append((a, b))
        for k in m:
            m[k].sort()
        return m

    g1 = group(s1)
    g2 = group(s2)
    keys = sorted(set(g1.keys()) | set(g2.keys()), key=lambda x: (x[0], x[1]))

    rows = []
    for sym, name in keys:
        l1 = g1.get((sym, name), [])
        l2 = g2.get((sym, name), [])
        m = max(len(l1), len(l2))
        for i in range(m):
            r1 = l1[i] if i < len(l1) else None
            r2 = l2[i] if i < len(l2) else None

            if r1:
                a1, b1 = r1
                s1z = b1 - a1
                st1 = hx(a1)
            else:
                a1 = b1 = 0
                s1z = 0
                st1 = "-"

            if r2:
                a2, b2 = r2
                s2z = b2 - a2
                st2 = hx(a2)
            else:
                a2 = b2 = 0
                s2z = 0
                st2 = "-"

            same = False
            if r1 and r2 and s1z == s2z:
                if a1 >= 0 and b1 <= len(d1) and a2 >= 0 and b2 <= len(d2):
                    same = (d1[a1:b1] == d2[a2:b2])

            addr = a1 if r1 else (a2 if r2 else 0)
            nm = name if i == 0 else f"{name}#{i}"
            rows.append((same, addr, sym, st1, st2, s1z, s2z, nm))

    rows.sort(key=lambda t: (t[0], t[1]))

    print("==== PCK Compare ====")
    print(f"pck1: {p1}  size={len(d1)} ({hx(len(d1))})")
    print(f"pck2: {p2}  size={len(d2)} ({hx(len(d2))})")
    print()
    print("SYM  START1      START2      SIZE1       SIZE2       SAME   NAME")
    print("---- ----------  ----------  ----------  ----------  -----  ----")

    for same, addr, sym, st1, st2, s1z, s2z, nm in rows:
        same_s = f"{str(bool(same)):<5}"
        print(f"{sym:>3}  {st1:<10}  {st2:<10}  {s1z:10d}  {s2z:10d}  {same_s}  {_dn(nm):<{NAME_W}}")

    return 0

def build_parser():
    ep = (
        "examples:\n"
        "  python ssd.py game.pck out_dir\n"
        "  python ssd.py -c 1.pck 2.pck\n"
        "\n"
        "export mode:\n"
        "  - dumps EVERY section shown in the map.\n"
        "  - output path comes from NAME (slashes create subfolders).\n"
        "  - name conflicts overwrite (no suffixing).\n"
        "\n"
        "compare mode (-c):\n"
        "  - compares sections grouped by (SYM, NAME).\n"
        "  - output is sorted with SAME=False first, then SAME=True; within each, by START address.\n"
    )
    p = argparse.ArgumentParser(
        prog="ssd.py",
        description="PCK section mapper + raw dumper + section comparer",
        epilog=ep,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument(
        "-c", "--compare",
        nargs=2,
        metavar=("PCK1", "PCK2"),
        help="compare two pck files by mapped sections (grouped by SYM+NAME)",
    )
    p.add_argument("pck", nargs="?", help="input .pck (export mode)")
    p.add_argument("out_dir", nargs="?", help="output directory (export mode)")
    return p

def main():
    ap = build_parser()
    args = ap.parse_args()

    if args.compare:
        return compare_pcks(args.compare[0], args.compare[1])

    if not args.pck or not args.out_dir:
        ap.print_help()
        return 2

    return dump_all_sections(args.pck, args.out_dir)

if __name__ == "__main__":
    raise SystemExit(main())
