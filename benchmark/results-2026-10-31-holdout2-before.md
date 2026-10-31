ArchiveGuard 0.11.0 · luật `a6ccef44a092` (heuristic dd1d591d33c2, yara 8a933f19b4bd, hashes 5e712f2e49c5) · Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, Python 3.13.17, 2 CPU

Mẫu: 92 (22 độc, 70 sạch); quét chưa đầy đủ: 2; thời gian/mẫu: trung vị 0.06 s, p95 13.43 s, max 21.35 s

### Dương tính khi kết luận ≥ ĐÁNG NGỜ

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 22 | 0 | 5 | 65 | 81.5% | 100.0% (85.1%–100.0%) | 89.8% | 7.1% (3.1%–15.7%) |
| Không dùng mã băm | 22 | 0 | 5 | 65 | 81.5% | 100.0% (85.1%–100.0%) | 89.8% | 7.1% (3.1%–15.7%) |
| Chỉ heuristic | 22 | 0 | 5 | 65 | 81.5% | 100.0% (85.1%–100.0%) | 89.8% | 7.1% (3.1%–15.7%) |

### Dương tính khi kết luận = NGUY HIỂM

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 5 | 17 | 0 | 70 | 100.0% | 22.7% (10.1%–43.4%) | 37.0% | 0.0% (0.0%–5.2%) |
| Không dùng mã băm | 5 | 17 | 0 | 70 | 100.0% | 22.7% (10.1%–43.4%) | 37.0% | 0.0% (0.0%–5.2%) |
| Chỉ heuristic | 5 | 17 | 0 | 70 | 100.0% | 22.7% (10.1%–43.4%) | 37.0% | 0.0% (0.0%–5.2%) |

### Recall theo họ (≥ ĐÁNG NGỜ)

| Họ | Số mẫu | Tất cả | Không dùng mã băm |
|---|---|---|---|
| credential_dump | 1 | 100.0% | 100.0% |
| defender_killer | 1 | 100.0% | 100.0% |
| double_extension | 1 | 100.0% | 100.0% |
| encrypted_exe | 1 | 100.0% | 100.0% |
| injector_loader | 1 | 100.0% | 100.0% |
| keylogger_native | 1 | 100.0% | 100.0% |
| keylogger_python | 1 | 100.0% | 100.0% |
| keylogger_smtp | 1 | 100.0% | 100.0% |
| known_rat_name | 1 | 100.0% | 100.0% |
| lnk_powershell | 1 | 100.0% | 100.0% |
| office_macro | 1 | 100.0% | 100.0% |
| packed_exe | 1 | 100.0% | 100.0% |
| ps_downloader | 1 | 100.0% | 100.0% |
| ransomware | 1 | 100.0% | 100.0% |
| reverse_shell_powershell | 1 | 100.0% | 100.0% |
| reverse_shell_python | 1 | 100.0% | 100.0% |
| rlo_file_name | 1 | 100.0% | 100.0% |
| stealer_browser | 1 | 100.0% | 100.0% |
| stealer_wallet | 1 | 100.0% | 100.0% |
| uac_bypass | 1 | 100.0% | 100.0% |
| usb_worm | 1 | 100.0% | 100.0% |
| vbs_dropper | 1 | 100.0% | 100.0% |

### Tỷ lệ báo nhầm theo nhóm phần mềm sạch (lớp Tất cả)

| Nhóm | Số mẫu | ≥ ĐÁNG NGỜ | = NGUY HIỂM |
|---|---|---|---|
| common | 51 | 5.9% | 0.0% |
| dual-use | 19 | 10.5% | 0.0% |

### Báo nhầm (mẫu sạch bị gắn cờ)

- `bufbuild-buf-win32-x64-1.75.0.tgz` (common) → suspicious: DOWNLOAD.EXEC_PS, NAME.EXECUTABLE
- `playwright-1.64.1-py3-none-win_amd64.whl` (common) → suspicious: DOWNLOAD.API, NAME.EXECUTABLE
- `pygame_ce-2.5.8-cp312-cp312-win_amd64.whl` (common) → suspicious: KEYLOG.API, NAME.EXECUTABLE
- `masky-0.2.1-py3-none-any.whl` (dual-use) → suspicious: NAME.EXECUTABLE, PACKER.ENTROPY
- `regedit-5.1.4.tgz` (dual-use) → suspicious: NAME.RISKY_TYPE

### Bỏ sót khi không dùng mã băm (mẫu độc bị coi là sạch)

- Không có
