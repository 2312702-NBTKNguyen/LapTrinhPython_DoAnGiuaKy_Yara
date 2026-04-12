rule Suspicious_Document_Script_Loader {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện hành vi tải mã độc qua tài liệu Office hoặc script đáng ngờ."
        date = "2026-03-18"
        severity = "high"
        category = "document_script"

    strings:
        $rtf = "{\\rtf" ascii nocase
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }

        $engine_1 = "wscript.shell" ascii wide nocase
        $engine_2 = "msxml2.xmlhttp" ascii wide nocase
        $engine_3 = "adodb.stream" ascii wide nocase
        $engine_4 = "activeXObject" ascii wide nocase

        $exec_1 = "powershell" ascii wide nocase
        $exec_2 = "cmd.exe" ascii wide nocase
        $exec_3 = "mshta" ascii wide nocase
        $exec_4 = "regsvr32" ascii wide nocase

        $net_1 = "http://" ascii wide nocase
        $net_2 = "https://" ascii wide nocase
        $net_3 = "download" ascii wide nocase

        $macro_1 = "AutoOpen" ascii wide nocase
        $macro_2 = "Document_Open" ascii wide nocase

    condition:
        filesize < 15MB and
        (
            (
                (1 of ($rtf, $ole)) and
                (1 of ($engine_*)) and
                (1 of ($exec_*, $net_*, $macro_*))
            )
            or
            (
                (2 of ($engine_*)) and
                (1 of ($exec_*)) and
                (1 of ($net_*))
            )
        )
}

rule Suspicious_Obfuscated_Script_Patterns {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện các mẫu script bị làm rối (obfuscated) thường dùng bởi dropper mã độc."
        date = "2026-03-18"
        severity = "high"
        category = "script_obfuscation"

    strings:
        $obf_1 = "fromCharCode" ascii wide nocase
        $obf_2 = "eval(" ascii wide nocase
        $obf_3 = "atob(" ascii wide nocase
        $obf_4 = "unescape(" ascii wide nocase
        $obf_5 = "replace(/\\\\x" ascii wide nocase

        $loader_1 = "wscript.shell" ascii wide nocase
        $loader_2 = "msxml2.xmlhttp" ascii wide nocase
        $loader_3 = "adodb.stream" ascii wide nocase
        $loader_4 = "powershell" ascii wide nocase
        $loader_5 = "cmd.exe /c" ascii wide nocase

        $net_1 = "http://" ascii wide nocase
        $net_2 = "https://" ascii wide nocase

    condition:
        filesize < 8MB and
        (
            (2 of ($obf_*)) and (1 of ($loader_*)) and (1 of ($net_*))
            or
            (1 of ($obf_*)) and (2 of ($loader_*))
        )
}

rule Suspicious_JS_ActiveX_Obfuscated_Dropper {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện JScript dropper dùng ActiveX bị làm rối nặng kết hợp kỹ thuật staging."
        date = "2026-03-18"
        severity = "high"
        category = "script_obfuscation"

    strings:
        $js_1 = "ActiveXObject(" ascii nocase
        $js_2 = "WScript.Quit" ascii nocase
        $js_3 = "new ActiveXObject" ascii nocase
        $js_4 = "RegExp" ascii nocase
        $js_5 = "Dictionary" ascii nocase
        $js_6 = "fromCharCode" ascii nocase
        $js_7 = "charCodeAt" ascii nocase
        $js_8 = "replace(" ascii nocase

    condition:
        filesize < 12MB and 
        uint16(0) != 0xFBFF and
        uint16(0) != 0xFAFF and
        uint32(0) != 0x474E5089 and
        4 of ($js_*)
}

rule Suspicious_OLE_Excel_Embedded_PDF {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện tài liệu Excel OLE nhúng nội dung PDF đáng ngờ."
        date = "2026-03-18"
        severity = "medium"
        category = "document_anomaly"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $xls = "Microsoft Office Excel Worksheet" ascii nocase
        $pdf = "%PDF-1." ascii nocase
        $acro1 = "Acrobat Document" ascii nocase
        $acro2 = "AcroExch.Document" ascii nocase

    condition:
        filesize < 25MB and $ole and $xls and $pdf and 1 of ($acro*)
}

rule Suspicious_RTF_Heavy_Obfuscation {
    meta:
        author = "Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long"
        description = "Phát hiện tài liệu RTF có mật độ mã rối cao bất thường."
        date = "2026-03-18"
        severity = "medium"
        category = "document_anomaly"

    strings:
        $rtf = "{\\rtf" ascii nocase
        $obj = "{\\*\\" ascii nocase
        $noise = /[\^\|`~@%]{3,}/ ascii
        $mix = /[\[\]\(\)\{\}\|\^~%]{6,}/ ascii

    condition:
        filesize < 15MB and ($rtf or $obj) and (#noise > 30 or #mix > 60)
}
