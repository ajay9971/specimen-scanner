rule EICAR_Test_File
{
    meta:
        description = "Harmless antivirus test string"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $e
}

rule Suspicious_Downloader_Strings
{
    meta:
        description = "Script/binary that downloads and runs something"
    strings:
        $a = "URLDownloadToFile" nocase
        $b = "powershell" nocase
        $c = "-enc" nocase
        $d = "DownloadString" nocase
        $e = "WScript.Shell" nocase
    condition:
        2 of them
}

rule Process_Injection_APIs
{
    meta:
        description = "Imports commonly used for process injection"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        all of them
}
