import "pe"

rule PE_Anomaly_HighEntropy {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện file PE có quá nhiều section (dấu hiệu bị đóng gói/packing)."
        date = "2026-03-18"
        severity = "medium"
        category = "pe_anomaly"

    condition:
        pe.is_pe and pe.number_of_sections > 8
}

rule Suspicious_Imports_ProcessInjection {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện file PE import các API tiêm mã vào tiến trình (Process Injection)."
        date = "2026-03-18"
        severity = "high"
        category = "suspicious_api"

    strings:
        $api1 = "VirtualAllocEx" ascii wide nocase
        $api2 = "WriteProcessMemory" ascii wide nocase
        $api3 = "CreateRemoteThread" ascii wide nocase
        $api4 = "NtUnmapViewOfSection" ascii wide nocase
        $api5 = "RtlCreateUserThread" ascii wide nocase

    condition:
        pe.is_pe and 3 of ($api*)
}

rule Suspicious_Imports_Persistence {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện file PE import các API dùng cho duy trì quyền truy cập (Persistence)."
        date = "2026-03-18"
        severity = "high"
        category = "suspicious_api"

    strings:
        $api1 = "RegSetValueEx" ascii wide nocase
        $api2 = "CreateService" ascii wide nocase
        $api3 = "StartService" ascii wide nocase
        $api4 = "SetWindowsHookEx" ascii wide nocase
        $api5 = "ChangeServiceConfig" ascii wide nocase

    condition:
        pe.is_pe and 3 of ($api*)
}

rule Suspicious_Imports_Evasion {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện kỹ thuật chống phân tích và né tránh (Anti-Analysis / Evasion)."
        date = "2026-03-18"
        severity = "medium"
        category = "evasion"

    strings:
        $api1 = "IsDebuggerPresent" ascii wide nocase
        $api2 = "CheckRemoteDebuggerPresent" ascii wide nocase
        $api3 = "NtQueryInformationProcess" ascii wide nocase
        $api4 = "GetTickCount" ascii wide nocase
        $api5 = "QueryPerformanceCounter" ascii wide nocase
        $api6 = "Sleep" ascii wide nocase

    condition:
        pe.is_pe and 4 of ($api*)
}

rule Packer_UPX {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện file thực thi được đóng gói bằng UPX."
        date = "2026-03-18"
        severity = "low"
        category = "packer"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = { 55 50 58 30 00 55 50 58 31 00 }

    condition:
        pe.is_pe and 2 of ($upx*)
}

rule Crypto_AES_Detection {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện triển khai mã hóa AES (dấu hiệu tiềm năng của ransomware)."
        date = "2026-03-18"
        severity = "medium"
        category = "crypto"

    strings:
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $aes1 = "AES" ascii wide nocase
        $aes2 = "Rijndael" ascii wide nocase
        $aes3 = "aes_encrypt" ascii wide nocase
        $aes4 = "aes_decrypt" ascii wide nocase

    condition:
        pe.is_pe and ($aes_sbox or 3 of ($aes*))
}

rule Crypto_RC4_Detection {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện triển khai mã hóa RC4."
        date = "2026-03-18"
        severity = "medium"
        category = "crypto"

    strings:
        $rc4_1 = "RC4" ascii wide nocase
        $rc4_2 = "ARC4" ascii wide nocase
        $rc4_3 = "rc4_setup" ascii wide nocase
        $rc4_4 = "rc4_crypt" ascii wide nocase

    condition:
        pe.is_pe and 2 of ($rc4_*)
}

rule Network_HardcodedIP {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện địa chỉ IP cứng tiềm ẩn dùng cho máy chủ điều khiển (C2)."
        date = "2026-03-18"
        severity = "medium"
        category = "network"

    strings:
        $ip1 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $ctx1 = "connect" ascii wide nocase
        $ctx2 = "sockaddr" ascii wide nocase
        $ctx3 = "socket" ascii wide nocase
        $ctx4 = "winsock" ascii wide nocase
        $ctx5 = "http://" ascii wide nocase
        $ctx6 = "https://" ascii wide nocase

    condition:
        filesize < 12MB and pe.is_pe and #ip1 >= 2 and 1 of ($ctx*)
}

rule Network_Tor_Indicators {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện dấu hiệu sử dụng mạng ẩn danh Tor."
        date = "2026-03-18"
        severity = "high"
        category = "network"

    strings:
        $tor1 = ".onion" ascii wide nocase
        $tor2 = "torproject.org" ascii wide nocase
        $tor3 = "torrc" ascii wide nocase
        $tor4 = "hidden_service" ascii wide nocase

    condition:
        pe.is_pe and 2 of ($tor*)
}

rule Shellcode_Common_Patterns {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện các mẫu shellcode phổ biến."
        date = "2026-03-18"
        severity = "high"
        category = "shellcode"

    strings:
        $shell1 = { FC E8 ?? 00 00 00 }
        $shell2 = { 64 8B 25 30 00 00 00 }
        $shell3 = { 64 8B 15 30 00 00 00 }
        $shell4 = { 64 A1 30 00 00 00 }

    condition:
        pe.is_pe and 2 of ($shell*)
} 
