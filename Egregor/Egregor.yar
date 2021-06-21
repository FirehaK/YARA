rule Egregor : ransomware
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2020-12-01"
        description = "Detects Egregor ransomware payloads by an encryption section"
        modified    = "2020-12-01"
        reference   = "personal research"
        tlp         = "WHITE"
    
    strings:

        // $xor_check = { 8b 84 24 [2] 00 00 31 ?? 33 84 24 [2] 00 00 3d [4] 0f 94 }
        
        // { b5006bb1 } : 0xbi6b00b5 (Egregor)
        // 1000d8ee  8b8424d4020000     mov     eax, dword [esp+0x2d4 {var_70c}]
        // 1000d8f5  31c9               xor     ecx, ecx  {0x0}
        // 1000d8f7  338424d0020000     xor     eax, dword [esp+0x2d0 {var_710}]
        // 1000d8fe  3db5006bb1         cmp     eax, 0xb16b00b5
        // 1000d903  0f94c1             sete    cl

        $section = { 8b 84 24 [2] 00 00 31 c9 33 84 24 [2] 00 00 3d b5 00 6b b1 0f 94 c1 }

    condition:
        $section
}
