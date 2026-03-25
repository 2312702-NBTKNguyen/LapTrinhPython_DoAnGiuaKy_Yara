import "pe"

rule Infostealer_AgentTesla {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện Agent Tesla dựa trên thư viện đặc trưng và hành vi gửi dữ liệu qua SMTP/Telegram."
        reference = "https://attack.mitre.org/software/S0331/"
        date = "2026-03-18"
        malware_family = "AgentTesla"
        severity = "high"

    strings:
        // Nhóm 1: Tín hiệu định danh (High Fidelity)
        $id_name = "AgentTesla" ascii wide nocase
        $id_dll  = "IELibrary.dll" ascii wide nocase // Thư viện kinh điển bị Agent Tesla lợi dụng

        // Nhóm 2: Kênh tuồn dữ liệu (Exfiltration Channels)
        $net_gmail = "smtp.gmail.com" ascii wide nocase
        $net_yahoo = "smtp.mail.yahoo.com" ascii wide nocase
        $net_tele  = "api.telegram.org/bot" ascii wide nocase

        // Nhóm 3: Từ khóa trong nội dung bị tuồn ra ngoài
        $steal_pw  = "Password:" ascii wide nocase
        $steal_log = "Keylogger" ascii wide nocase

    condition:
        // Đảm bảo là file PE (EXE/DLL)
        pe.is_pe and 
        (
            // Kịch bản 1: Để lộ tên hoặc thư viện độc quyền -> Báo động ngay
            any of ($id_*)
            or
            // Kịch bản 2: Ứng dụng gửi email/telegram NHƯNG nội dung chứa các từ khóa nhạy cảm
            (1 of ($net_*) and 1 of ($steal_*))
        )
}