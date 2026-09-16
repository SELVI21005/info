rule Suspicious_PowerShell : scripting execution {
    meta:
        description = "Detects common PowerShell execution strings"
        category = "script"
        severity = "medium"
    strings:
        $powershell = "powershell.exe" nocase ascii wide
        $powershell_name = "powershell" nocase ascii wide
        $encoded = "-enc" nocase ascii wide
        $invoke = "invoke-expression" nocase ascii wide
        $download = "downloadstring" nocase ascii wide
    condition:
        1 of them
}

rule Suspicious_Command_Shell : scripting execution {
    meta:
        description = "Detects suspicious Windows command shell usage"
        category = "script"
        severity = "medium"
    strings:
        $cmd = "cmd.exe" nocase ascii wide
        $shell = "command shell" nocase ascii wide
        $wscript = "wscript.exe" nocase ascii wide
        $cscript = "cscript.exe" nocase ascii wide
    condition:
        1 of them
}

rule Suspicious_Process_Create : windows_api process {
    meta:
        description = "Detects process creation API references"
        category = "api"
        severity = "medium"
    strings:
        $create_process_a = "CreateProcessA" ascii wide
        $create_process_w = "CreateProcessW" ascii wide
        $create_remote = "CreateRemoteThread" ascii wide
        $win_exec = "WinExec" ascii wide
    condition:
        1 of them
}

rule Suspicious_Persistence_Strings : persistence {
    meta:
        description = "Detects common persistence-related strings"
        category = "persistence"
        severity = "medium"
    strings:
        $run_key = "software\\microsoft\\windows\\currentversion\\run" nocase ascii wide
        $startup = "\\startup" nocase ascii wide
        $scheduled_task = "schtasks" nocase ascii wide
        $service_create = "sc create" nocase ascii wide
    condition:
        1 of them
}

rule Suspicious_Script_Patterns : scripting {
    meta:
        description = "Detects suspicious script construction patterns"
        category = "script"
        severity = "low"
    strings:
        $base64 = "base64" nocase ascii wide
        $obfuscation = "frombase64string" nocase ascii wide
        $eval = "eval(" nocase ascii wide
        $payload = "payload" nocase ascii wide
    condition:
        2 of them
}
