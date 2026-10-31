ArchiveGuard 0.12.0 · luật `5fdb333d8776` (heuristic 4d9c2f3325a3, yara 8a933f19b4bd, hashes 5e712f2e49c5) · Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, Python 3.13.17, 2 CPU

Mẫu: 109 (0 độc, 109 sạch); quét chưa đầy đủ: 0; thời gian/mẫu: trung vị 0.18 s, p95 11.0 s, max 27.91 s

### Dương tính khi kết luận ≥ ĐÁNG NGỜ

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 3 | 106 | 0.0% | – | – | 2.8% (0.9%–7.8%) |
| Không dùng mã băm | 0 | 0 | 3 | 106 | 0.0% | – | – | 2.8% (0.9%–7.8%) |
| Chỉ heuristic | 0 | 0 | 3 | 106 | 0.0% | – | – | 2.8% (0.9%–7.8%) |

### Dương tính khi kết luận = NGUY HIỂM

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 1 | 108 | 0.0% | – | – | 0.9% (0.2%–5.0%) |
| Không dùng mã băm | 0 | 0 | 1 | 108 | 0.0% | – | – | 0.9% (0.2%–5.0%) |
| Chỉ heuristic | 0 | 0 | 1 | 108 | 0.0% | – | – | 0.9% (0.2%–5.0%) |

### Tỷ lệ báo nhầm theo nhóm phần mềm sạch (lớp Tất cả)

| Nhóm | Số mẫu | ≥ ĐÁNG NGỜ | = NGUY HIỂM |
|---|---|---|---|
| common | 93 | 2.2% | 0.0% |
| dual-use | 16 | 6.2% | 6.2% |

### Báo nhầm (mẫu sạch bị gắn cờ)

- `electron-winstaller-5.4.4.tgz` (common) → suspicious: NAME.RISKY_TYPE
- `pywin32-312-cp312-cp312-win_amd64.whl` (common) → suspicious: NAME.RISKY_TYPE
- `impacket-0.13.1-py3-none-any.whl` (dual-use) → malicious: EXEC.PS_HIDDEN, RANSOM.KILL_BACKUP, STEAL.CREDENTIAL_DUMP

### Bỏ sót khi không dùng mã băm (mẫu độc bị coi là sạch)

- Không có
