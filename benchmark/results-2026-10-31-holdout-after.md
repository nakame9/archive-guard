ArchiveGuard 0.7.0 · luật `2e803535739a` (heuristic d03b61361959, yara 8a933f19b4bd, hashes 5e712f2e49c5) · Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, Python 3.13.17, 2 CPU

Mẫu: 81 (0 độc, 81 sạch); quét chưa đầy đủ: 0; thời gian/mẫu: trung vị 0.31 s, p95 5.71 s, max 17.95 s

### Dương tính khi kết luận ≥ ĐÁNG NGỜ

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 6 | 75 | 0.0% | – | – | 7.4% (3.4%–15.2%) |
| Không dùng mã băm | 0 | 0 | 6 | 75 | 0.0% | – | – | 7.4% (3.4%–15.2%) |
| Chỉ heuristic | 0 | 0 | 6 | 75 | 0.0% | – | – | 7.4% (3.4%–15.2%) |

### Dương tính khi kết luận = NGUY HIỂM

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 0 | 81 | – | – | – | 0.0% (0.0%–4.5%) |
| Không dùng mã băm | 0 | 0 | 0 | 81 | – | – | – | 0.0% (0.0%–4.5%) |
| Chỉ heuristic | 0 | 0 | 0 | 81 | – | – | – | 0.0% (0.0%–4.5%) |

### Tỷ lệ báo nhầm theo nhóm phần mềm sạch (lớp Tất cả)

| Nhóm | Số mẫu | ≥ ĐÁNG NGỜ | = NGUY HIỂM |
|---|---|---|---|
| common | 71 | 4.2% | 0.0% |
| dual-use | 10 | 30.0% | 0.0% |

### Báo nhầm (mẫu sạch bị gắn cờ)

- `cmake-4.4.4-py3-none-win_amd64.whl` (common) → suspicious: KEYLOG.API, NAME.EXECUTABLE
- `pip-26.2.2-py3-none-any.whl` (common) → suspicious: BACKDOOR.REVERSE_SHELL
- `virtualenv-21.15.1-py3-none-any.whl` (common) → suspicious: BACKDOOR.REVERSE_SHELL
- `bloodhound-1.9.0-py3-none-any.whl` (dual-use) → suspicious: STEAL.CREDENTIAL_DUMP
- `pyinjector-1.4.0-cp312-cp312-win_amd64.whl` (dual-use) → suspicious: INJECT.PROCESS
- `pypykatz-0.6.13-py3-none-any.whl` (dual-use) → suspicious: INJECT.PROCESS, STEAL.BROWSER, STEAL.CREDENTIAL_DUMP

### Bỏ sót khi không dùng mã băm (mẫu độc bị coi là sạch)

- Không có
