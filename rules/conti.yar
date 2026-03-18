rule Ransomware_Conti {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện Conti ransomware dựa trên sự kết hợp giữa ransom note, thông điệp và link darkweb."
        reference = "https://attack.mitre.org/software/S0575/"
        date = "2026-03-18"
        malware_family = "Conti"
        severity = "high"

    strings:
        // Nhóm 1: Dấu hiệu Tên định danh
        $id_conti = "CONTI" ascii wide nocase
        $id_ext   = ".CONTI" ascii wide nocase // Đuôi file mã hóa của các biến thể đời đầu

        // Nhóm 2: Các yếu tố tạo nên một cuộc tống tiền (Generic Ransomware)
        $msg_enc   = "All of your files are encrypted" ascii wide nocase
        $msg_tor   = "TOR browser" ascii wide nocase // Conti luôn hối thúc nạn nhân tải Tor
        $net_onion = ".onion" ascii wide nocase
        $file_note = "readme.txt" ascii wide nocase

    condition:
        // Đảm bảo là file PE (EXE/DLL)
        uint16(0) == 0x5A4D and 
        (
            // Kịch bản 1: Để lộ thẳng đuôi file mã hóa .CONTI -> Chắc chắn là mã độc
            $id_ext
            or
            // Kịch bản 2: Có nhắc tên CONTI, kèm theo câu tống tiền hoặc link .onion
            ($id_conti and 1 of ($msg_enc, $msg_tor, $net_onion))
            or
            // Kịch bản 3: Biến thể ẩn tên, nhưng có đầy đủ combo
            ($file_note and $msg_enc and $net_onion)
        )
}