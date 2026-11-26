/*
  MailSleuth local YARA rules (offline, default-safe heuristics).
  These are lightweight indicators; matches raise suspicion/malice depending on rule meta.
*/

rule EICAR_Test_String {
  meta:
    description = "EICAR antivirus test string"
    severity = "high"
    verdict = "malicious"
  strings:
    $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $e
}

rule Suspicious_PowerShell_Encoded {
  meta:
    description = "PowerShell encoded/obfuscated execution markers"
    severity = "medium"
    verdict = "suspicious"
  strings:
    $a = /powershell(.{0,40})-(enc|encodedcommand)\b/i ascii wide
    $b = /frombase64string/i ascii wide
    $c = /iex\s*\(|invoke-expression/i ascii wide
  condition:
    any of them
}

rule Suspicious_Script_Dropper {
  meta:
    description = "Common script dropper/LOLBin markers"
    severity = "medium"
    verdict = "suspicious"
  strings:
    $a = /\b(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript)\b/i ascii wide
    $b = /http[s]?:\/\/[^\s"'<>]{8,}/i ascii wide
    $c = /\b(cmd\.exe|powershell\.exe)\b/i ascii wide
  condition:
    ($a and $b) or ($a and $c)
}

rule Office_Macro_AutoExec_Hints {
  meta:
    description = "Office/VBA auto-exec macro hints in binary/text"
    severity = "medium"
    verdict = "suspicious"
  strings:
    $a = "AutoOpen" ascii wide nocase
    $b = "Document_Open" ascii wide nocase
    $c = "AutoExec" ascii wide nocase
    $d = "Workbook_Open" ascii wide nocase
    $e = "Shell" ascii wide
    $f = "CreateObject" ascii wide
  condition:
    2 of them
}

rule PDF_Active_Content_Hints {
  meta:
    description = "PDF active content/action markers"
    severity = "medium"
    verdict = "suspicious"
  strings:
    $a = "/JavaScript" ascii
    $b = "/JS" ascii
    $c = "/OpenAction" ascii
    $d = "/AA" ascii
    $e = "/Launch" ascii
    $f = "/EmbeddedFile" ascii
    $g = "/RichMedia" ascii
  condition:
    2 of them
}
