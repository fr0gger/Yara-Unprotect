/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule Qemu_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for QEMU Registry Key"
	strings:
		$desc1 = "HARDWARE\\Description\\System" nocase wide ascii
		$desc2 = "SystemBiosVersion" nocase wide ascii
		$desc3 = "QEMU" wide nocase ascii

		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$dev2 = "Identifier" nocase wide ascii
		$dev3 = "QEMU" wide nocase ascii
	condition:
		any of ($desc*) or any of ($dev*)
}

rule VBox_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for VBOX Registry Key"
	strings:
		$desc1 = "HARDWARE\\Description\\System" nocase wide ascii
		$desc2 = "SystemBiosVersion" nocase wide ascii
		$desc3 = "VideoBiosVersion" nocase wide ascii

		$data1 = "VBOX" nocase wide ascii
		$data2 = "VIRTUALBOX" nocase wide ascii
		
		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$dev2 = "Identifier" nocase wide ascii
		$dev3 = "VBOX" nocase wide ascii

		$soft1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
		$soft2 = "HARDWARE\\ACPI\\DSDT\\VBOX__"
		$soft3 = "HARDWARE\\ACPI\\FADT\\VBOX__"
		$soft4 = "HARDWARE\\ACPI\\RSDT\\VBOX__"
		$soft5 = "SYSTEM\\ControlSet001\\Services\\VBoxGuest"
		$soft6 = "SYSTEM\\ControlSet001\\Services\\VBoxService"
		$soft7 = "SYSTEM\\ControlSet001\\Services\\VBoxMouse"
		$soft8 = "SYSTEM\\ControlSet001\\Services\\VBoxVideo"

		$virtualbox1 = "VBoxHook.dll" nocase
	        $virtualbox2 = "VBoxService" nocase
        	$virtualbox3 = "VBoxTray" nocase
        	$virtualbox4 = "VBoxMouse" nocase
        	$virtualbox5 = "VBoxGuest" nocase
        	$virtualbox6 = "VBoxSF" nocase
        	$virtualbox7 = "VBoxGuestAdditions" nocase
        	$virtualbox8 = "VBOX HARDDISK"  nocase
        	$virtualbox9 = "VBoxVideo" nocase
		$virtualbox10 = "vboxhook" nocase
		$virtualbox11 = "vboxmrxnp" nocase
		$virtualbox12 = "vboxogl" nocase
		$virtualbox13 = "vboxoglarrayspu" nocase
		$virtualbox14 = "vboxoglcrutil"
		$virtualbox15 = "vboxoglerrorspu" nocase
		$virtualbox16 = "vboxoglfeedbackspu" nocase
		$virtualbox17 = "vboxoglpackspu" nocase
		$virtualbox18 = "vboxoglpassthroughspu" nocase
		$virtualbox19 = "vboxcontrol" nocase

        	// VirtualBox Mac Address
        	$virtualbox_mac_1a = "08-00-27"
        	$virtualbox_mac_1b = "08:00:27"
        	$virtualbox_mac_1c = "080027"	
	condition:
		any of ($desc*) and 
		1 of ($data*) or 
		any of ($dev*) or 
		any of ($soft*) or
		any of ($virtualbox*)
}

rule VMWare_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for VMWARE Registry Key"
	strings:
		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
		$dev2 = "Identifier" wide nocase ascii
		$dev3 = "VMware" wide nocase ascii
		$soft ="SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide

		// Random strings related to Vmware
		$vmware = {56 4D 58 68}
        	$vmware1 = "VMXh"
        	$vmware2 = "Ven_VMware_" nocase
        	$vmware3 = "Prod_VMware_Virtual_" nocase
        	$vmware4 = "hgfs.sys" nocase
        	$vmware5 = "vmhgfs.sys" nocase
        	$vmware6 = "prleth.sys" nocase
        	$vmware7 = "prlfs.sys" nocase
        	$vmware8 = "prlmouse.sys" nocase
        	$vmware9 = "prlvideo.sys" nocase
        	$vmware10 = "prl_pv32.sys" nocase
        	$vmware11 = "vpc-s3.sys" nocase
        	$vmware12 = "vmsrvc.sys" nocase
        	$vmware13 = "vmx86.sys" nocase
        	$vmware14 = "vmnet.sys" nocase
        	$vmware15 = "vmicheartbeat" nocase
        	$vmware16 = "vmicvss" nocase
        	$vmware17 = "vmicshutdown" nocase
        	$vmware18 = "vmicexchange" nocase
        	$vmware19 = "vmdebug" nocase
        	$vmware20 = "vmmouse" nocase
        	$vmware21 = "vmtools" nocase
        	$vmware22 = "VMMEMCTL" nocase
       		$vmware23 = "vmx86" nocase
        	$vmware24 = "vmware" nocase
        	$vmware25 = "vmware.exe" nocase
        	$vmware26 = "vmware-authd.exe" nocase
        	$vmware27 = "vmware-hostd.exe" nocase
        	$vmware28 = "vmware-tray.exe" nocase
        	$vmware29 = "vmware-vmx.exe" nocase
        	$vmware30 = "vmnetdhcp.exe" nocase
        	$vmware31 = "vpxclient.exe" nocase
    		$vmware32 = { b868584d56bb00000000b90a000000ba58560000ed }
		$vmware34 = "VMware Virtual IDE Hard Drive" ascii wide
		$vmware35 = "VMwareService.exe" nocase
		$vmware36 = "Vmwaretray.exe" nocase
		$vmware37 = "TPAutoConnSvc.exe" nocase
		$vmware38 = "Vmwareuser.exe" nocase		

    		// Vmware Mac Address
    		$vmware_mac_1a = "00-05-69"
        	$vmware_mac_1b = "00:05:69"
        	$vmware_mac_1c = "000569"
        	$vmware_mac_2a = "00-50-56"
        	$vmware_mac_2b = "00:50:56"
        	$vmware_mac_2c = "005056"
        	$vmware_mac_3a = "00-0C-29" nocase
        	$vmware_mac_3b = "00:0C:29" nocase
        	$vmware_mac_3c = "000C29" nocase
        	$vmware_mac_4a = "00-1C-14" nocase
        	$vmware_mac_4b = "00:1C:14" nocase
        	$vmware_mac_4c = "001C14" nocase
	condition:
		any of ($dev*) or $soft or 
		any of ($vmware*)
}

rule VM_Detect_VirtualPC_XEN_Wine
{
	meta:
        	author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        	description = "Xen detection, VirtualPC, Red Pill, Wine and other"
	strings:
        	// Binary tricks
        	$virtualpc = {0F 3F 07 0B}
        	$ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        	$vmcheckdll = {45 C7 00 01}
        	$redpill = {0F 01 0D 00 00 00 00 C3}

        	$virtualpc1 = "vpcbus" nocase
        	$virtualpc2 = "vpc-s3" nocase
        	$virtualpc3 = "vpcuhub" nocase
        	$virtualpc4 = "msvmmouf" nocase

        	$xen1 = "xenevtchn" nocase
        	$xen2 = "xennet" nocase
        	$xen3 = "xennet6" nocase
        	$xen4 = "xensvc" nocase
        	$xen5 = "xenvdb" nocase
        	$xen6 = "XenVMM" nocase
        	$xen7 = "xenservice.exe" nocase

        	$wine1 = "wine_get_unix_file_name" ascii wide
	condition:
        	any of them
}

rule VM_Detect_Username_Filepath_DriveSize
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Check filepaths and drive size and Sandbox usernames"
	strings:
		// Filepaths
		$path1 = "SANDBOX" wide ascii
		$path2 = "\\SAMPLE" wide ascii
		$path3 = "\\VIRUS" wide ascii

		// Drive Size
		$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO	

		// Sandbox usernames
		$user1 = "MALTEST" wide ascii
		$user2 = "TEQUILABOOMBOOM" wide ascii
		$user3 = "SANDBOX" wide ascii
		$user4 = "VIRUS" wide ascii
		$user5 = "MALWARE" wide ascii
	condition:
		all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA") or
		pe.imports("kernel32.dll","CreateFileA") and 	
		pe.imports("kernel32.dll","DeviceIoControl") and 
		$dwIoControlCode and $physicaldrive or
		all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}

rule Anti_Automated_Sandbox
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Check JoeSandbox, Anubis, Threat Expert, Sandboxie, Cwsandbox"
    	strings:
    		// joe sandbox
		$joe1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
		$joe2 = "RegQueryValue" 
		$joe3 = "55274-640-2673064-23950"

		// anubis 
		$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        	$c1 = "RegQueryValue" 
        	$s1 = "76487-337-8429955-22614" 
        	$s2 = "76487-640-1457236-23837"

        	// threat expert
        	$f1 = "dbghelp.dll" nocase 

        	// sandboxie
        	$f2 = "SbieDLL.dll" nocase

        	// cwsandbox
        	$var1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        	$var2 = "76487-644-3177037-23510" 

    	condition:
        	any of ($joe*) or 
        	$p1 and $c1 and 1 of ($s*) or
        	1 of ($f*) or
        	all of ($var*)
}
