/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule Disable_Antivirus 
{
   meta:
	author = "x0r"
	description = "Disable AntiVirus"

    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase

        $c1 = "RegSetValue" 

        $r1 = "AntiVirusDisableNotify" 
        $r2 = "DontReportInfectionInformation" 
        $r3 = "DisableAntiSpyware" 
        $r4 = "RunInvalidSignatures" 
        $r5 = "AntiVirusOverride" 
        $r6 = "CheckExeSignatures"

        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase

    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule Disable_UAC 
{
    meta:
        author = "x0r"
        description = "Disable User Access Control"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule Disable_Firewall 
{
    meta:
        author = "x0r"
        description = "Disable Firewall"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue" 
        $r1 = "FirewallPolicy" 
        $r2 = "EnableFirewall" 
        $r3 = "FirewallDisableNotify" 
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule Disable_Dep 
{
    meta:
        author = "x0r"
        description = "Bypass DEP"
    strings:
        $c1 = "EnableExecuteProtectionSupport" 
        $c2 = "NtSetInformationProcess" 
        $c3 = "VirtualProctectEx" 
        $c4 = "SetProcessDEPPolicy" 
        $c5 = "ZwProtectVirtualMemory" 
    condition:
        any of them
}

rule Inject_Certificate 
{
    meta:
        author = "x0r"
        description = "Inject certificate in store"
    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore" 
    condition:
	all of them
}

rule Escalate_Priv 
{
    meta:
        author = "x0r"
        description = "Escalade priviledges"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege" 
        $c2 = "AdjustTokenPrivileges" 
    condition:
        1 of ($d*) and 1 of ($c*)
}
