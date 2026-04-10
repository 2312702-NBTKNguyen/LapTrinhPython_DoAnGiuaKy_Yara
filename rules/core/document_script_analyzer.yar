rule Suspicious_Document_Script_Loader {
    meta:
        description = "Detects suspicious Office/script loader behavior in non-PE files"
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
        description = "Detects obfuscated script patterns often used by malware droppers"
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
        description = "Detects heavily obfuscated JScript droppers using ActiveX and staging primitives"
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
        filesize < 12MB and 4 of ($js_*)
}

rule Suspicious_OLE_Excel_Embedded_PDF {
    meta:
        description = "Detects Excel OLE documents embedding PDF content/object handlers"
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
        description = "Detects RTF documents with dense obfuscation patterns"
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
