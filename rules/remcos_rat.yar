import "pe"

rule RAT_Remcos {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện Remcos RAT dựa trên chuỗi liên quan điều khiển từ xa và hành vi duy trì quyền truy cập (Persistence)."
		reference = "https://attack.mitre.org/software/S0332/"
		date = "2026-03-18"
		malware_family = "RemcosRAT"
		severity = "high"

	strings:
        // Nhóm 1: Dấu hiệu Tín hiệu mạnh (High Fidelity) - Chỉ có trong Remcos
        $str_remcos = "Remcos" ascii wide nocase
        $str_vendor = "BreakingSecurity.net" ascii wide nocase // Trang web gốc bán phần mềm Remcos
        $str_klog   = "[klog]" ascii wide nocase             // Định dạng đánh dấu file log ghi âm/bàn phím của Remcos

        // Nhóm 2: Các cờ cấu hình (Config markers) từ Remcos Builder
        $cfg_host   = "Host:Port" ascii wide nocase
        $cfg_install = "Install flag" ascii wide nocase
        $cfg_mutex  = "MUTEX" ascii wide nocase

        // Nhóm 3: Hành vi duy trì quyền truy cập (Persistence)
        $beh_runkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase

    condition:
        pe.is_pe and 
        (
            // Kịch bản 1: File bất cẩn để lộ tên Remcos hoặc tên vendor -> Chắc chắn là mã độc
            any of ($str_*)
            or
            // Kịch bản 2: Mã độc xóa tên, nhưng để lại nguyên cụm cấu hình (ít nhất 2 cờ) + hành vi ghi Registry
            (2 of ($cfg_*) and $beh_runkey)
            or
            // Kịch bản 3: File chứa đầy đủ cả 3 cờ cấu hình đặc trưng của Builder
            all of ($cfg_*)
        )
}
