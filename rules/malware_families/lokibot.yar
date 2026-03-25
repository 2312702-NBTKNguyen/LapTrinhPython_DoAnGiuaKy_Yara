import "pe"

rule Infostealer_LokiBot {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện LokiBot dựa trên chuỗi exfiltration FTP/SMTP và keylogging."
		reference = "https://attack.mitre.org/software/S0431/"
		date = "2026-03-18"
		malware_family = "LokiBot"
		severity = "high"

	strings:
        // Nhóm 1: Dấu hiệu Mạng/C2 đặc trưng (High Fidelity)
        $c2_fre     = "fre.php" ascii wide nocase
        $c2_pvq     = "PvqDqcv.php" ascii wide nocase
        $ua_charon  = "Mozilla/4.08 (Charon; Inferno)" ascii wide nocase // User-Agent kinh điển của Loki

        // Nhóm 2: Các mục tiêu đánh cắp thông tin ưu tiên của LokiBot
        $tgt_filezilla = "FileZilla\\sitemanager.xml" ascii wide nocase
        $tgt_winscp    = "Software\\Martin Prikryl\\WinSCP 2\\Sessions" ascii wide nocase
        $tgt_foxmail   = "Foxmail" ascii wide nocase
        $tgt_thunderbird = "Thunderbird\\Profiles" ascii wide nocase

        // Nhóm 3: Chuỗi hành vi
        $beh_ftp    = "ftp://" ascii wide nocase
        $beh_smtp   = "smtp." ascii wide nocase
        $api_fgw    = "GetForegroundWindow" ascii
        $api_gks    = "GetAsyncKeyState" ascii

    condition:
        // Đảm bảo là file PE (EXE/DLL)
        pe.is_pe and 
        (
            // Kịch bản 1: Để lộ đường dẫn C2 hoặc User-Agent độc quyền -> Chắc chắn là LokiBot
            any of ($c2_*) or $ua_charon
            or
            // Kịch bản 2: Nhắm vào ít nhất 2 ứng dụng mục tiêu cụ thể VÀ có API ghi phím/gửi mạng
            (2 of ($tgt_*) and 1 of ($beh_*, $api_*))
        )
}
