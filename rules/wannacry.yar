import "pe"

rule Ransomware_WannaCry {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện mã độc tống tiền WannaCry dựa trên các chuỗi đặc trưng và hành vi."
        reference_1 = "https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware"
        reference_2 = "https://attack.mitre.org/software/S0366/"
        date = "2026-03-18"
        malware_family = "WannaCry"
        severity = "high"

    strings:
        // Tên miền kill-switch xuất hiện trong các biến thể WannaCry ban đầu.
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii nocase

        // Dùng tiền tố $ioc_ cho tất cả các dấu vết còn lại để dễ nhóm trong condition
        $ioc_svc_name     = "mssecsvc2.0" ascii nocase
        $ioc_task_binary  = "tasksche.exe" ascii nocase
        $ioc_decryptor    = "@WanaDecryptor@.exe" ascii nocase
        $ioc_task_dl      = "taskdl.exe" ascii nocase
        $ioc_readme       = "@Please_Read_Me@.txt" ascii nocase
        $ioc_ransom_title = "Wanna Decryptor" ascii wide nocase
        $ioc_ransom_text  = "Oops, your files have been encrypted!" ascii wide nocase
        $ioc_ext_wncry    = ".WNCRY" ascii nocase
        $ioc_ext_wnry     = ".WNRY" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            // Tín hiệu mạnh: có kill-switch và ít nhất 1 dấu vết khác.
            ($killswitch and 1 of ($ioc_*))
            or
            // Trường hợp biến thể đã bị vá kill-switch: cần ít nhất 4 dấu vết.
            (4 of ($ioc_*))
        )
}