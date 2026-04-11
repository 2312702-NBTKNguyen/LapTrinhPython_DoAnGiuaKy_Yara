import "pe"

rule PE_Anomaly_HighEntropy {
    meta:
        description = "Detects PE files with multiple sections (potential packing)"
        severity = "medium"
        category = "pe_anomaly"

    condition:
        pe.is_pe and pe.number_of_sections > 8
}

rule Suspicious_Imports_ProcessInjection {
    meta:
        description = "Detects PE files importing process injection APIs"
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
        description = "Detects PE files importing persistence-related APIs"
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
        description = "Detects anti-analysis and evasion techniques"
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
        description = "Detects UPX packed executables"
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
        description = "Detects AES crypto implementation (potential ransomware)"
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
        description = "Detects RC4 crypto implementation"
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
        description = "Detects potential C2 hardcoded IPs with network context"
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
        description = "Detects Tor network indicators"
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
        description = "Detects common shellcode patterns"
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
