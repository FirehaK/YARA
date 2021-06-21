rule SUSP_Small_VHD_or_VHDX : suspicious vhd vhdx
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2019-12-20"
        description = "A rule to hunt for suspiciously small VHD and VHDX files"
        modified    = "2019-12-22"
        reference   = "https://www.virustotal.com/gui/file/3382a75bd959d2194c4b1a8885df93e8770f4ebaeaff441a5180ceadf1656cd9/detection"
        tlp         = "WHITE"
    
    strings:
        // conectix
        $vhd_cookie = { 63 6F 6E 65 63 74 69 78 }
        // vhdxfile
        $vhdx_signature = { 76 68 64 78 66 69 6c 65 }
    
    condition:
        ($vhd_cookie at 0 or $vhdx_signature at 0)
        and filesize <= 5MB
}
