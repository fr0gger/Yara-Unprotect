/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule AtomTable_Inject
{
    meta:
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = " Detect AtomBombing technique"
    strings:
        $var1 = "GlobalAddAtom"
        $var2 = "GlobalGetAtomName"
        $var3 = "QueueUserAPC"
    condition:
        all of them
}

rule DLL_inject
{
    meta:
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = "Check for DLL Injection"
    strings:
        $var1 = "OpenProcess"
        $var2 = "VirtualAllocEx"
        $var3 = "LoadLibraryA"
        $var4 = "CreateFileA"
        $var5 = "WriteProcessMemory"
        $var6 = "HeapAlloc"
        $var7 = "GetProcAddress"
        $var8 = "CreateRemoteThread"
    condition:
        4 of them
}

rule Inject_Thread 
{
    meta:
        author = "x0r modified by @fr0gger_"
        description = "Code injection with CreateRemoteThread in a remote process"
    strings:
        $c1 = "OpenProcess" 
        $c2 = "VirtualAllocEx" 
        $c3 = "NtWriteVirtualMemory" 
        $c4 = "WriteProcessMemory" 
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c1 )
}

rule Win_Hook 
{
    meta:
        author = "x0r"
        description = "Affect hook table"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"         
    condition:
        $f1 and 1 of ($c*)
}
