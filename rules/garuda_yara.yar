rule GARUDA_EICAR_Test_File {
    meta:
        description = "Industry-standard EICAR anti-malware verification signature"
        severity = "critical"
        category = "virus"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule GARUDA_Reverse_Shell_Script {
    meta:
        description = "Detects bash, netcat, or obfuscated PowerShell reverse-shell commands"
        severity = "critical"
        category = "reverse_shell"
    strings:
        $bash = "/dev/tcp/" nocase
        $nc = "nc -e /bin/" nocase
        $ps1 = "DownloadString(" nocase
        $ps2 = "Invoke-Expression" nocase
    condition:
        $bash or $nc or ($ps1 and $ps2)
}

rule GARUDA_Cryptominer_Stratum {
    meta:
        description = "Detects hidden cryptocurrency miner pool references"
        severity = "warning"
        category = "cryptominer"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $s3 = "xmrig" nocase
    condition:
        any of them
}

rule GARUDA_Ransomware_Backup_Wipe {
    meta:
        description = "Detects shadow-copy deletion commands typical of ransomware"
        severity = "critical"
        category = "ransomware"
    strings:
        $vss = "vssadmin delete shadows" nocase
        $wb = "wbadmin delete catalog" nocase
    condition:
        any of them
}
