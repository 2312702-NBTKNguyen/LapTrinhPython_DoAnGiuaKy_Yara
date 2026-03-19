import "pe"

rule RAT_njRAT {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện njRAT dựa trên chuỗi điều khiển từ xa và persistence trên Windows."
		reference = "https://attack.mitre.org/software/S0385/"
		date = "2026-03-18"
		malware_family = "njRAT"
		severity = "high"

	strings:
        // Nhóm 1: Dấu hiệu đặc trưng cao (High Fidelity) - Gần như chắc chắn là njRAT
        $str_njrat = "njRAT" ascii wide nocase
        $str_njq8  = "njq8" ascii wide nocase // Biệt danh tác giả
        $net_delim = "|'|'|" ascii wide // Ký tự phân cách mạng kinh điển của njRAT
        $net_endof = "[endof]" ascii wide nocase // Một delimiter khác hay dùng cho keylogger

        // Nhóm 2: Các cờ/hành vi thường gặp (Behavioral/Generic)
        $beh_runkey   = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $beh_cmd      = "cmd.exe /c" ascii wide nocase
        $beh_pastebin = "Pastebin" ascii wide nocase
        // SEE_MASK_NOZONECHECKS thường được njRAT dùng để bỏ qua cảnh báo bảo mật khi chạy file tải từ mạng
        $beh_env      = "SEE_MASK_NOZONECHECKS" ascii wide 

    condition:
        pe.is_pe and 
        (
            // Kịch bản 1: Có tên mã độc HOẶC có chuỗi phân cách mạng độc quyền (Chỉ cần 1 là đủ kết luận)
            any of ($str_*) or any of ($net_*)
            or
            // Kịch bản 2: Mã độc giấu kỹ thông tin, yêu cầu phải gom đủ 3 hành vi mờ ám mới báo động
            (3 of ($beh_*))
        )
}
