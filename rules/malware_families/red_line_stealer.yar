import "pe"

rule Infostealer_RedLineStealer {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện RedLineStealer dựa trên hành vi gom dữ liệu trình duyệt, ví crypto và Discord."
		reference = "https://attack.mitre.org/software/S0483/"
		date = "2026-03-18"
		malware_family = "RedLineStealer"
		severity = "high"

	strings:
        // Nhóm 1: Dấu hiệu định danh (Thường bị hacker ẩn đi, nhưng nếu có thì cực kỳ đáng ngờ)
        $id_name = "RedLine" ascii wide nocase
        $id_wcf  = "net.tcp://" ascii wide nocase // RedLine thường dùng giao thức này (WCF) để gửi dữ liệu về C2

        // Nhóm 2: Mục tiêu trình duyệt (Chromium/Gecko)
        $br_login  = "Login Data" ascii wide nocase
        $br_local  = "Local State" ascii wide nocase // Chứa key giải mã
        $br_cookie = "Network\\Cookies" ascii wide nocase // Đường dẫn cụ thể thay vì chỉ dùng chữ "Cookies"
        $br_web    = "Web Data" ascii wide nocase

        // Nhóm 3: Mục tiêu ứng dụng & Crypto (Đặc sản của RedLine)
        $tgt_wallet  = "wallet.dat" ascii wide nocase // Cụ thể hóa đuôi file ví
        $tgt_discord = "discord\\Local Storage\\leveldb" ascii wide nocase // Đường dẫn trộm token Discord
        $tgt_tele    = "tdata" ascii wide nocase // Thư mục chứa session Telegram

    condition:
        // Phải là file PE (EXE/DLL)
        pe.is_pe and 
        (
            // Kịch bản 1: Bất cẩn để lộ tên RedLine HOẶC dùng giao thức net.tcp + 1 hành vi trộm cắp
            (any of ($id_*) and 1 of ($br_*, $tgt_*))
            or
            // Kịch bản 2: Không có tên mã độc, nhưng có DẤU HIỆU KẾT HỢP (Trộm cả Trình duyệt VÀ Ví/App chat)
            (2 of ($br_*) and 1 of ($tgt_*))
        )
}
