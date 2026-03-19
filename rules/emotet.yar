import "pe"

rule BankingTrojan_Emotet {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện Emotet Dropper dựa trên chuỗi lệnh PowerShell ẩn và kỹ thuật tải từ WordPress."
        reference = "https://attack.mitre.org/software/S0367/"
        date = "2026-03-18"
        malware_family = "Emotet"
        severity = "high"

    strings:
        // Nhóm 1: Tên định danh (Hiếm khi xuất hiện, nhưng có thể có ở file unpack)
        $id_emotet = "Emotet" ascii wide nocase

        // Nhóm 2: Lệnh PowerShell đặc trưng của Emotet Dropper
        $ps_cmd    = "powershell" ascii wide nocase
        $ps_window = "-w hidden" ascii wide nocase
        $ps_enc    = "-enc" ascii wide nocase
        $ps_web    = "Net.WebClient" ascii wide nocase
        $ps_down   = "DownloadFile" ascii wide nocase

        // Nhóm 3: Dấu vết mạng (Chỉ có giá trị khi đi kèm với Nhóm 2)
        $net_wp    = "/wp-content/" ascii wide nocase // Các site WordPress bị hack làm C2
        $net_http  = "http://" ascii wide nocase

    condition:
        // Đảm bảo là file PE (EXE/DLL)
        pe.is_pe and 
        (
            // Kịch bản 1: Để lộ tên định danh
            $id_emotet
            or
            // Kịch bản 2: Chuỗi hành vi Dropper kinh điển
            // Nới ngưỡng để giảm bỏ sót biến thể đã pack/obfuscate
            (
                2 of ($ps_*)
                and 1 of ($net_*)
            )
        )
}