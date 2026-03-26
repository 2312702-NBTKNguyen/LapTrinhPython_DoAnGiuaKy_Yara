"""
Regression tests cho toàn bộ malware family rules.

Mục tiêu: đảm bảo các IOC tối thiểu vẫn kích hoạt đúng rule
kể cả khi mẫu không phải PE (trừ Mirai dùng ELF).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yara


RULESET_PATH = "rules/index.yar"


def _build_samples() -> dict[str, bytes]:
    # IOC payload tối thiểu cho từng family rule.
    return {
        "BankingTrojan_Emotet": b"powershell -w hidden -enc Net.WebClient http://evil/wp-content/",
        "Ransomware_Conti": b"readme.txt All of your files are encrypted TOR browser .onion",
        "BankingTrojan_Dridex": b"Dridex <webinjects> <set_url> POST User-Agent:",
        "Infostealer_Formbook": b"Formbook WinHttpOpen WinHttpSendRequest GetAsyncKeyState nss3.dll",
        "Ransomware_LockBit": b"Restore-My-Files.txt Your files are encrypted TOX ID:",
        "Infostealer_LokiBot": b"fre.php ftp:// FileZilla\\sitemanager.xml MSXML2.XMLHTTP",
        "Infostealer_AgentTesla": b"AgentTesla smtp.gmail.com Password: WScript.Shell",
        "RAT_Remcos": b"Remcos BreakingSecurity.net Host:Port MUTEX Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "BankingTrojan_TrickBot": b"<mcconf> injectDll group_tag powershell",
        "Botnet_Mirai": b"\x7fELFMIRAI /dev/watchdog telnet busybox",
        "RAT_njRAT": b"njRAT |'|'| [endof] cmd.exe /c Pastebin SEE_MASK_NOZONECHECKS",
        "Infostealer_RedLineStealer": b"RedLine net.tcp:// Login Data Local State wallet.dat",
        "Ransomware_Ryuk": b"RyukReadMe bitcoin shadow copies vssadmin.exe Delete Shadows",
        "Ransomware_WannaCry": b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com mssecsvc2.0 tasksche.exe",
    }


def main() -> int:
    rules = yara.compile(filepath=RULESET_PATH)

    failures: list[str] = []
    for expected_rule, sample in _build_samples().items():
        hits = [m.rule for m in rules.match(data=sample)]
        if expected_rule not in hits:
            failures.append(f"{expected_rule}: MISS -> {hits}")
        else:
            print(f"[OK] {expected_rule}")

    if failures:
        print("\n[FAIL] Rule coverage regression:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("\n[PASS] All malware family rules matched expected IOC samples.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
