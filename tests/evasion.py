"""Evasion corpus: các mẫu ZIP cố tình làm khó trình quét, dựng từng byte lúc chạy test (repo không chứa file nhị phân).

Mỗi mẫu: (hàm dựng, kết luận mong đợi, có vùng byte chưa giải thích được không, ghi chú).
Từ M2b, mẫu ghi chú "UNEXPLAINED_BYTES" ra CHƯA QUÉT ĐỦ vì còn byte chưa giải thích.
Mẫu ghi chú "chưa phủ" là lỗ hổng đã biết mà độ phủ cấu trúc KHÔNG bắt được.
"""
import io
import struct
import zipfile

from helpers import (
    EICAR,
    FAKE_EXE,
    _zip_parts,
    make_7z,
    make_pe,
    make_zip,
    set_encrypted_flag,
    zip_with_hidden,
    zip_with_overlap,
)


def _hidden_with_flags(flags):
    b = bytearray(zip_with_hidden({"readme.txt": b"xin chao"}, {"payload.exe": FAKE_EXE}))
    pos = b.find(b"PK\x03\x04", 1)  # local header thứ hai = entry ẩn
    b[pos + 6] |= flags
    return bytes(b)


def _gap_between_entries():
    """Byte lạ chèn giữa hai entry: danh mục vẫn đúng (offset được dời theo)."""
    local1, cd1, _ = _zip_parts(make_zip({"a.txt": b"aaaa"}))
    local2, cd2, _ = _zip_parts(make_zip({"b.txt": b"bbbb"}))
    gap = b"\x00" + EICAR + b"\x00"
    cd2 = bytearray(cd2)
    struct.pack_into("<I", cd2, 42, len(local1) + len(gap))  # offset local header của b.txt
    cd = cd1 + bytes(cd2)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 2, 2, len(cd), len(local1) + len(gap) + len(local2), 0)
    return local1 + gap + local2 + cd + eocd


def _duplicate_names():
    import warnings
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z, warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # zipfile cảnh báo tên trùng – chính là điều cần dựng
        z.writestr("tai-lieu.txt", b"vo hai")
        z.writestr("tai-lieu.txt", EICAR)  # cùng tên: trình giải nén thường giữ bản sau, đè lên bản trước
    return buf.getvalue()


def _comment(payload):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"a")
        z.comment = payload
    return buf.getvalue()


def _extra_field_payload():
    """Payload nằm trong extra field của local header: hợp lệ về cấu trúc, không trình giải nén nào lấy ra."""
    local, cd, eocd = _zip_parts(make_zip({"a.txt": b"a"}))
    extra = struct.pack("<HH", 0xCAFE, len(EICAR)) + EICAR
    name_len = struct.unpack_from("<H", local, 26)[0]
    local = local[:28] + struct.pack("<H", len(extra)) + local[30:30 + name_len] + extra + local[30 + name_len:]
    struct.pack_into("<I", eocd, 16, len(local))
    return local + cd + bytes(eocd)


def _nested(depth, payload):
    data = payload
    for i in range(depth):
        data = make_zip({f"lop{i}.zip" if i else "e.com": data})
    return data


CORPUS = {
    "hidden_entry_payload": (lambda: zip_with_hidden({"a.txt": b"a"}, {"e.com": EICAR}), "malicious", True, ""),
    "hidden_entry_data_descriptor": (lambda: _hidden_with_flags(0x08), "suspicious", True, "HIDDEN_UNSCANNED"),
    "hidden_entry_encrypted": (lambda: _hidden_with_flags(0x01), "suspicious", True, "HIDDEN_UNSCANNED"),
    "overlapping_entries": (lambda: zip_with_overlap("a.txt", b"A" * 4096), "suspicious", False, ""),
    "junk_prefix": (lambda: b"\x00JUNK" * 20 + make_zip({"e.com": EICAR}), "malicious", True, ""),
    "pe_sfx": (lambda: make_pe([(".text", b"\x90" * 512, 0x60000020)]) + make_zip({"e.com": EICAR}),
               "malicious", False, ""),
    "trailing_junk": (lambda: make_zip({"a.txt": b"a"}) + b"\x00" * 64, "incomplete", True, "UNEXPLAINED_BYTES"),
    "gap_between_entries": (_gap_between_entries, "incomplete", True, "UNEXPLAINED_BYTES"),
    "pdf_prefix_trailing_junk": (lambda: b"%PDF-1.7\n" + make_zip({"a.txt": b"a"}) + b"\x00" * 64,
                                 "incomplete", True, "UNEXPLAINED_BYTES"),
    "duplicate_names": (_duplicate_names, "malicious", False, ""),
    "nested_3_levels": (lambda: _nested(3, EICAR), "malicious", False, ""),
    "nested_too_deep": (lambda: _nested(7, b"vo hai"), "suspicious", False, ""),
    "rlo_name": (lambda: make_zip({"photo‮gpj.scr": FAKE_EXE}), "malicious", False, ""),
    "double_extension": (lambda: make_zip({"hoa-don.pdf.exe": FAKE_EXE}), "suspicious", False, ""),
    "encrypted_exe": (lambda: set_encrypted_flag(make_zip({"setup.exe": FAKE_EXE})), "suspicious", False, ""),
    "7z_inside_zip": (lambda: make_zip({"a.7z": make_7z({"e.com": EICAR})}), "malicious", False, ""),
    "comment_payload": (lambda: _comment(EICAR), "clean", False, "chưa phủ: nội dung comment không được quét"),
    "extra_field_payload": (_extra_field_payload, "clean", False, "chưa phủ: nội dung extra field không được quét"),
}
