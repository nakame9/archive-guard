ArchiveGuard 0.12.0 · luật `5fdb333d8776` (heuristic 4d9c2f3325a3, yara 8a933f19b4bd, hashes 5e712f2e49c5) · Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, Python 3.13.17, 2 CPU

Mẫu: 81 (0 độc, 81 sạch); quét chưa đầy đủ: 0; thời gian/mẫu: trung vị 0.31 s, p95 5.93 s, max 17.67 s

### Dương tính khi kết luận ≥ ĐÁNG NGỜ

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 2 | 79 | 0.0% | – | – | 2.5% (0.7%–8.6%) |
| Không dùng mã băm | 0 | 0 | 2 | 79 | 0.0% | – | – | 2.5% (0.7%–8.6%) |
| Chỉ heuristic | 0 | 0 | 2 | 79 | 0.0% | – | – | 2.5% (0.7%–8.6%) |

### Dương tính khi kết luận = NGUY HIỂM

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 0 | 81 | – | – | – | 0.0% (0.0%–4.5%) |
| Không dùng mã băm | 0 | 0 | 0 | 81 | – | – | – | 0.0% (0.0%–4.5%) |
| Chỉ heuristic | 0 | 0 | 0 | 81 | – | – | – | 0.0% (0.0%–4.5%) |

### Tỷ lệ báo nhầm theo nhóm phần mềm sạch (lớp Tất cả)

| Nhóm | Số mẫu | ≥ ĐÁNG NGỜ | = NGUY HIỂM |
|---|---|---|---|
| common | 71 | 0.0% | 0.0% |
| dual-use | 10 | 20.0% | 0.0% |

### Báo nhầm (mẫu sạch bị gắn cờ)

- `bloodhound-1.9.0-py3-none-any.whl` (dual-use) → suspicious: STEAL.CREDENTIAL_DUMP
- `pypykatz-0.6.13-py3-none-any.whl` (dual-use) → suspicious: STEAL.BROWSER, STEAL.CREDENTIAL_DUMP

### Bỏ sót khi không dùng mã băm (mẫu độc bị coi là sạch)

- Không có
