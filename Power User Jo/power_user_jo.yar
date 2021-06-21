rule Power_User_Jo : ransomware
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2021-02-15"
        description = "simple string to hunt a new/unknown ransomware"
        modified    = "2021-02-15"
        reference   = "Internal research"
        tlp         = "WHITE"
    
    strings:
        $s1 = "power_user_jo" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d
        and filesize <= 100KB
        and $s1
}
