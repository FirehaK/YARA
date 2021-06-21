rule Sekhmet : ransomware
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2020-12-01"
        description = "Detects Sekhmet ransomware payloads by an encryption section"
        modified    = "2020-12-01"
        reference   = "personal research"
        tlp         = "WHITE"
    
    strings:

        // $xor_check = { 8b 84 24 [2] 00 00 31 ?? 33 84 24 [2] 00 00 3d [4] 0f 94 }

        // { bebaadde } : 0xdeadbabe (Sekhmet)
        // 1000d1a2  8b8424d0020000     mov     eax, dword [esp+0x2d0 {var_710}]
        // 1000d1a9  31db               xor     ebx, ebx  {0x0}
        // 1000d1ab  338424cc020000     xor     eax, dword [esp+0x2cc {var_714}]
        // 1000d1b2  3dbebaadde         cmp     eax, 0xdeadbabe
        // 1000d1b7  0f94c3             sete    bl

        $section = { 8b 84 24 [2] 00 00 31 db 33 84 24 [2] 00 00 3d be ba ad de 0f 94 c3 }

    condition:
        $section
}
