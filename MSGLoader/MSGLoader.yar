rule MSGLoader
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2020-12-04"
        description = "MSGLoader is a loader for Maze, Sekhmet and Egregor ransomware payloads."
        modified    = "2020-12-11"
        reference   = "https://twitter.com/_FirehaK/status/1335113044700110848"
        tlp         = "WHITE"
    
    strings:
        $Salsa20_constant = /expand (16|32)-byte k/

        // ==========================================================
        // block from Salsa20 implementation (typically Egregor, Sekhmet payloads)
        // ==========================================================
        
        // 1001adc5  c1e0??             shl     eax, 0x7
        // 1001adc8  8b4d??             mov     ecx, dword [ebp-0x18]
        // 1001adcb  334d??             xor     ecx, dword [ebp-0x28]
        // 1001adce  c1e9??             shr     ecx, 0x19
        // 1001a5e3  09c8               or      eax, ecx
        $Salsa20_01 = { c1e0?? 8b4d?? 334d?? c1e9?? 09c8 }

        // ==========================================================
        // blocks from Sosemanuk implementation (typically Maze payload)
        // ==========================================================

        // 10007998  8b85??ffffff       mov     eax, dword [ebp-0xf4]
        // 1000799e  8985??ffffff       mov     dword [ebp-0x90], eax
        // 100079a4  8b4d??             mov     ecx, dword [ebp-0x4]
        // 100079a7  898d????ffff       mov     dword [ebp-0x198], ecx
        // 100079ad  8b55??             mov     edx, dword [ebp-0xc]
        // 100079b0  0395??ffffff       add     edx, dword [ebp-0x90]
        // 100079b6  8955??             mov     dword [ebp-0x4], edx
        // 100079b9  6985????ffff07536554   imul    eax, dword [ebp-0x198], 0x54655307
        $Sosemanuk_01 = { 8b85??ffffff 8985??ffffff 8b4d?? 898d????ffff 8b55?? 0395??ffffff 8955?? 6985????ffff07536554 }

        // 10007bd9  8b85????ffff       mov     eax, dword [ebp-0x1a0]
        // 10007bdf  8945??             mov     dword [ebp-0x58], eax
        // 10007be2  8b45??             mov     eax, dword [ebp-0x2c]
        // 10007be5  8945??             mov     dword [ebp-0x5c], eax
        // 10007be8  8b45??             mov     eax, dword [ebp-0x30]
        // 10007beb  0345??             add     eax, dword [ebp-0x58]
        // 10007bee  8945??             mov     dword [ebp-0x2c], eax
        // 10007bf1  6945??07536554     imul    eax, dword [ebp-0x5c], 0x54655307
        $Sosemanuk_02 = { 8b85????ffff 8945?? 8b45?? 8945?? 8b45?? 0345?? 8945?? 6945??07536554 }

        // ==========================================================
        // stack string CryptStringToBinaryA
        // ==========================================================

        // 10006a5e  8d4c2404           lea     ecx, [esp+0x4]
        // 10006a62  c644241800         mov     byte [esp+0x18], 0x0
        // 10006a67  c744241461727941   mov     dword [esp+0x14], 0x41797261
        // 10006a6f  c74424106f42696e   mov     dword [esp+0x10], 0x6e69426f
        // 10006a77  c744240c696e6754   mov     dword [esp+0xc], 0x54676e69
        // 10006a7f  c744240874537472   mov     dword [esp+0x8], 0x72745374
        // 10006a87  c744240443727970   mov     dword [esp+0x4], 0x70797243
        // 10006a8f  51                 push    ecx
        // 10006a90  50                 push    eax
        // 10006a91  ff1510e00b10       call    dword [GetProcAddress@IAT]
        // $CryptStringToBinaryA = { 8d4c2404 c644241800 c744241461727941 c74424106f42696e c744240c696e6754 c744240874537472 c744240443727970 51 50 ff15 }

        // 10006a30  c644241400         mov     byte [esp+0x14], 0x0
        // 10006a35  c744241061727941   mov     dword [esp+0x10], 0x41797261
        // 10006a3d  c744240c6f42696e   mov     dword [esp+0xc], 0x6e69426f
        // 10006a45  c7442408696e6754   mov     dword [esp+0x8], 0x54676e69
        // 10006a4d  c744240474537472   mov     dword [esp+0x4], 0x72745374
        // 10006a55  c7042443727970     mov     dword [esp], 0x70797243
        // 10006a5c  89e1               mov     ecx, esp
        // 10006a5e  51                 push    ecx
        // 10006a5f  50                 push    eax
        // 10006a60  ff151cc00910       call    dword [GetProcAddress@IAT]
        $CryptStringToBinaryA = { c64424??00 c74424??61727941 c74424??6f42696e c74424??696e6754 c74424??74537472 (c7442404|c70424)43727970 (89e1 51| 51) 50 ff15 }
    condition:
        uint16(0) == 0x5a4d
        and (
            2 of ($Salsa20_*)
            or 1 of ($Sosemanuk_*)
            or $CryptStringToBinaryA
        )
}
