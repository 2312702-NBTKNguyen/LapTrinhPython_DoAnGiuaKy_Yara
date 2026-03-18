rule Botnet_Mirai {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện Mirai botnet trên Linux/IoT dựa vào chuỗi quét và tài khoản mặc định."
		reference = "https://attack.mitre.org/software/S0225/"
		date = "2026-03-18"
		malware_family = "Mirai"
		severity = "high"

	strings:
        // Nhóm 1: Các chuỗi "trứ danh" từ mã nguồn Mirai bị rò rỉ
        $mirai_name  = "MIRAI" ascii nocase
        $mirai_joke  = "I love chicken nuggets" ascii nocase // Chuỗi debug nổi tiếng trong source Mirai
        $mirai_watch = "/dev/watchdog" ascii nocase // Mirai can thiệp watchdog để ngăn thiết bị tự khởi động lại
        $mirai_bind  = "bind() failed" ascii nocase // Thông báo lỗi mạng thường gặp trong file binary của nó

        // Nhóm 2: Từ điển Brute-force đặc trưng của Mirai (Không tìm 'root' chung chung, mà tìm combo mật khẩu)
        // Đây là những mật khẩu mặc định của các dòng camera Dahua, router ZTE... mà Mirai chuyên săn lùng
        $cred_1 = "xc3511" ascii     // Mật khẩu đi kèm user root
        $cred_2 = "vizxv" ascii      // Mật khẩu camera IP
        $cred_3 = "xmhdipc" ascii
        $cred_4 = "888888" ascii
        $cred_5 = "default" ascii

        // Nhóm 3: Môi trường mục tiêu
        $env_busybox = "busybox" ascii nocase
        $env_telnet  = "telnet" ascii nocase

    condition:
        // Đảm bảo là file ELF (Linux/IoT binary)
        uint32(0) == 0x464C457F and 
        (
            // Kịch bản 1: Có chứa các chuỗi "chữ ký" độc quyền của Mirai
            any of ($mirai_*)
            or
            // Kịch bản 2: Mã độc được biên dịch lại để giấu tên, nhưng vẫn vác theo 
            // từ điển mật khẩu đặc trưng để đi hack, cộng thêm việc gọi telnet/busybox.
            (3 of ($cred_*) and $env_busybox and $env_telnet)
        )
}
