ArchiveGuard 0.7.0 · luật `2e803535739a` (heuristic d03b61361959, yara 8a933f19b4bd, hashes 5e712f2e49c5) · Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, Python 3.13.17, 2 CPU

Mẫu: 109 (0 độc, 109 sạch); quét chưa đầy đủ: 0; thời gian/mẫu: trung vị 0.26 s, p95 13.69 s, max 33.15 s

### Dương tính khi kết luận ≥ ĐÁNG NGỜ

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 16 | 93 | 0.0% | – | – | 14.7% (9.2%–22.5%) |
| Không dùng mã băm | 0 | 0 | 16 | 93 | 0.0% | – | – | 14.7% (9.2%–22.5%) |
| Chỉ heuristic | 0 | 0 | 16 | 93 | 0.0% | – | – | 14.7% (9.2%–22.5%) |

### Dương tính khi kết luận = NGUY HIỂM

| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |
|---|---|---|---|---|---|---|---|---|
| Tất cả | 0 | 0 | 1 | 108 | 0.0% | – | – | 0.9% (0.2%–5.0%) |
| Không dùng mã băm | 0 | 0 | 1 | 108 | 0.0% | – | – | 0.9% (0.2%–5.0%) |
| Chỉ heuristic | 0 | 0 | 1 | 108 | 0.0% | – | – | 0.9% (0.2%–5.0%) |

### Tỷ lệ báo nhầm theo nhóm phần mềm sạch (lớp Tất cả)

| Nhóm | Số mẫu | ≥ ĐÁNG NGỜ | = NGUY HIỂM |
|---|---|---|---|
| common | 93 | 6.5% | 0.0% |
| dual-use | 16 | 62.5% | 6.2% |

### Báo nhầm (mẫu sạch bị gắn cờ)

- `electron-winstaller-5.4.4.tgz` (common) → suspicious: DOWNLOAD.API, NAME.EXECUTABLE, NAME.RISKY_TYPE, PERSIST.AUTOSTART
- `pygame-2.6.1-cp312-cp312-win_amd64.whl` (common) → suspicious: KEYLOG.API, NAME.EXECUTABLE
- `pyside6_essentials-6.12.0-cp310-abi3-win_amd64.whl` (common) → suspicious: KEYLOG.API, NAME.EXECUTABLE
- `pywin32-312-cp312-cp312-win_amd64.whl` (common) → suspicious: INJECT.PROCESS, KEYLOG.API, NAME.RISKY_TYPE, WORM.NETWORK
- `ruff-0.17.3-py3-none-win_amd64.whl` (common) → suspicious: BACKDOOR.KNOWN_RAT, NAME.EXECUTABLE
- `wxpython-4.3.2-cp312-cp312-win_amd64.whl` (common) → suspicious: KEYLOG.API, NAME.EXECUTABLE
- `ahk_binary-2025.1.0-py3-none-any.whl` (dual-use) → suspicious: KEYLOG.API, NAME.EXECUTABLE
- `debugpy-1.8.22-cp312-cp312-win_amd64.whl` (dual-use) → suspicious: INJECT.PROCESS, NAME.EXECUTABLE
- `frida-17.24.3-cp37-abi3-win_amd64.whl` (dual-use) → suspicious: INJECT.PROCESS
- `impacket-0.13.1-py3-none-any.whl` (dual-use) → malicious: EXEC.PS_HIDDEN, RANSOM.KILL_BACKUP, STEAL.CREDENTIAL_DUMP
- `keyboard-0.13.5-py3-none-any.whl` (dual-use) → suspicious: KEYLOG.API
- `node-pty-1.1.0.tgz` (dual-use) → suspicious: BACKDOOR.REVERSE_SHELL, KEYLOG.API, NAME.EXECUTABLE
- `pymem-1.14.0-py3-none-any.whl` (dual-use) → suspicious: INJECT.PROCESS
- `pynput-1.8.2-py2.py3-none-any.whl` (dual-use) → suspicious: KEYLOG.API
- `pywinpty-3.1.2-cp312-cp312-win_amd64.whl` (dual-use) → suspicious: BACKDOOR.REVERSE_SHELL, KEYLOG.API, NAME.EXECUTABLE
- `uiohook-napi-1.5.5.tgz` (dual-use) → suspicious: KEYLOG.API

### Bỏ sót khi không dùng mã băm (mẫu độc bị coi là sạch)

- Không có
