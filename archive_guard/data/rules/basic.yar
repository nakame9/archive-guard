/*
  Luật YARA đi kèm ArchiveGuard. Phần meta được dùng để chấm điểm:
    severity    = "low" | "medium" | "high" | "critical"
    category    = known_malware | trojan | keylogger | worm | ransomware | stealer
                  | backdoor | downloader | evasion | generic
    description = mô tả hiển thị trong báo cáo

  Thêm luật: bỏ file .yar vào thư mục này, hoặc chạy với --yara <file/thư mục>.
  Bộ luật cộng đồng nên thử: github.com/Yara-Rules/rules, github.com/Neo23x0/signature-base
*/

rule EICAR_Test_File
{
    meta:
        description = "File thử nghiệm EICAR (vô hại, dùng để kiểm tra trình quét)"
        severity = "critical"
        category = "known_malware"
    strings:
        $head = "X5O!P%@AP[4"
        $body = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $head at 0 and $body
}

rule PHP_Webshell
{
    meta:
        description = "Webshell PHP: chạy lệnh hệ thống lấy từ tham số HTTP"
        severity = "high"
        category = "backdoor"
    strings:
        $php = "<?php" nocase
        $exec = /(system|shell_exec|passthru|exec|popen|proc_open|assert|eval)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $packed = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase
    condition:
        $php and ($exec or $packed)
}
