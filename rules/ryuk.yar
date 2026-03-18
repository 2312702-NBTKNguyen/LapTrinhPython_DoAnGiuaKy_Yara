rule Ransomware_Ryuk {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện Ryuk ransomware dựa trên chuỗi ransom note, đuôi mã hóa và hành vi đặc trưng."
        reference = "https://attack.mitre.org/software/S0446/"
        date = "2026-03-18"
        malware_family = "Ryuk"
        severity = "high"

    strings:
        // Nhóm 1: Dấu hiệu đặc trưng cao (High Fidelity) của Ryuk
        $ryuk_note = "RyukReadMe" ascii wide nocase
        $ryuk_ext  = ".RYK" ascii wide nocase // Đuôi file sau khi bị mã hóa

        // Nhóm 2: Hành vi/Dấu hiệu chung (Behavioral / Generic)
        $beh_wol    = "Wake on LAN" ascii wide nocase
        $beh_vss    = "shadow copies" ascii wide nocase
        // Lệnh xóa backup kinh điển mà Ryuk hay dùng:
        $beh_cmd    = "vssadmin.exe Delete Shadows" ascii wide nocase 
        $beh_crypto = "bitcoin" ascii wide nocase

    condition:
        // Phải là file thực thi Windows (EXE/DLL)
        uint16(0) == 0x5A4D and 
        (
            // Tín hiệu mạnh: Chỉ cần có tên Ransom note hoặc đuôi .RYK là đủ kết luận
            1 of ($ryuk_*)
            or
            // Trường hợp biến thể ẩn tên, phải gom đủ ít nhất 3 hành vi đáng ngờ mới được báo động
            3 of ($beh_*)
        )
}
