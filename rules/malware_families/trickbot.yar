import "pe"

rule BankingTrojan_TrickBot {
	meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
		description = "Phát hiện TrickBot dựa trên chuỗi module và giao tiếp C2."
		reference = "https://attack.mitre.org/software/S0266/"
		date = "2026-03-18"
		malware_family = "TrickBot"
		severity = "high"

	strings:
        // Nhóm 1: Các tags đặc trưng trong file cấu hình (Config XML) của TrickBot
        $xml_mcconf   = "<mcconf>" ascii wide nocase
        $xml_module   = "<moduleconfig>" ascii wide nocase
        $xml_autorun  = "<autostart>" ascii wide nocase

        // Nhóm 2: Tên các module con mà TrickBot thường tải về và inject
        $mod_inject   = "injectDll" ascii wide nocase
        $mod_system   = "systeminfo" ascii wide nocase
        $mod_pwgrab   = "pwgrab" ascii wide nocase       // Module chuyên trộm mật khẩu
        $mod_network  = "networkDll" ascii wide nocase

        // Nhóm 3: Các tham số giao tiếp C2 (Command & Control)
        $c2_group_tag = "group_tag" ascii wide nocase 
        $c2_client_id = "client_id" ascii wide nocase

    condition:
        pe.is_pe and 
        (
            // Dấu hiệu cực mạnh: Chứa ít nhất 2 thẻ cấu hình XML của Trickbot
            2 of ($xml_*) 
            or
            // Dấu hiệu mạnh: Chứa ít nhất 3 tên module con đặc trưng
            2 of ($mod_*) 
            or
            // Dấu hiệu kết hợp: Có thẻ XML + Module + Tham số C2
            (1 of ($xml_*) and 1 of ($mod_*) and 1 of ($c2_*))
        )
}
