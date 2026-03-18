rule Infostealer_Formbook {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện Formbook/XLoader dựa trên API mạng cấp thấp, tiêm tiến trình và mục tiêu trình duyệt."
        reference = "https://attack.mitre.org/software/S0447/"
        date = "2026-03-18"
        malware_family = "Formbook"
        severity = "high"

    strings:
        // Nhóm 1: Dấu hiệu Tên định danh (High Fidelity)
        $id_formbook = "Formbook" ascii wide nocase
        $id_xloader  = "XLoader" ascii wide nocase // Biến thể đời mới của Formbook

        // Nhóm 2: Các hàm API mạng cấp thấp
        $api_net_open = "WinHttpOpen" ascii
        $api_net_send = "WinHttpSendRequest" ascii

        // Nhóm 3: Các hàm API Hooking và Injection
        $api_key      = "GetAsyncKeyState" ascii
        $api_hook     = "SetWindowsHookEx" ascii // Bắt phím (Keylogger) toàn hệ thống
        $api_hollow   = "NtUnmapViewOfSection" ascii // Hàm kinh điển dùng để Process Hollowing

        // Nhóm 4: Mục tiêu đánh cắp
        $tgt_nss3     = "nss3.dll" ascii wide nocase // Thư viện giải mã mật khẩu của họ Firefox
        $tgt_sqlite   = "mozsqlite3.dll" ascii wide nocase

    condition:
        // Đảm bảo là file PE (EXE/DLL)
        uint16(0) == 0x5A4D and 
        (
            // Kịch bản 1: Lộ tên định danh (Chắc chắn là mã độc)
            any of ($id_*)
            or
            // Kịch bản 2: Kết hợp Hành vi (Mạng + Keylogger + Nhắm mục tiêu)
            // Phải có gửi mạng qua WinHttp, có bắt phím/hook, VÀ tìm kiếm file mật khẩu
            (all of ($api_net_*) and 1 of ($api_key, $api_hook) and 1 of ($tgt_*))
            or
            // Kịch bản 3: Mã độc tiêm tiến trình (Process Hollowing) kết hợp mạng
            (all of ($api_net_*) and $api_hollow)
        )
}