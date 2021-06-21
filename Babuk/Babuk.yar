rule Babuk : babuk babyk ransomware
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2021-01-21"
        description = "Babuk / Babyk ransomware"
        modified    = "2021-05-06"
        reference   = "http://chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/"
        tlp         = "WHITE"
    
    strings:
        // false positives
        $primerose = "Primerose Loader" ascii

        // $decrypt_* strings are found only in the decryptor
        $decrypt_01 = "Press 'OK' to start decryption process!" ascii
        $decrypt_02 = "Your files decrypted, bye!" ascii
        $decrypt_03 = "Key broken!" wide

        $mutex_01 = "DoYouWantToHaveSexWithCoungDong" ascii
        $mutex_02 = "babuk_v2" ascii
        $mutex_03 = "babuk_v3" ascii

        // the number of these back-to-back calls can differ, I've only included one
        // 00406818  e853030000         call    sub_406b70
        // 0040681d  e85ec9ffff         call    sub_403180
        // 00406822  e809c1ffff         call    sub_402930
        // 00406827  e864c3ffff         call    sub_402b90
        // 0040682c  e8ffbfffff         call    sub_402830
        // 00406831  6a07               push    0x7
        // 00406833  6a00               push    0x0
        // 00406835  6a00               push    0x0
        // 00406837  ff1548914000       call    dword [SHEmptyRecycleBinA@IAT]
        $empty_bins = { e8[4] 6a07 6a00 6a00 ff15 }

        // 00405a4b  c78540e2ffff63686f75   mov     dword [ebp-0x1dc0 {var_1dc4}], 0x756f6863
        // 00405a55  c78544e2ffff6e672064   mov     dword [ebp-0x1dbc {var_1dc0}], 0x6420676e
        // 00405a5f  c78548e2ffff6f6e6720   mov     dword [ebp-0x1db8 {var_1dbc}], 0x20676e6f
        // 00405a69  c7854ce2ffff6c6f6f6b   mov     dword [ebp-0x1db4 {var_1db8}], 0x6b6f6f6c
        // 00405a73  c78550e2ffff73206c69   mov     dword [ebp-0x1db0 {var_1db4}], 0x696c2073
        // 00405a7d  c78554e2ffff6b652068   mov     dword [ebp-0x1dac {var_1db0}], 0x6820656b
        // 00405a87  c78558e2ffff6f742064   mov     dword [ebp-0x1da8 {var_1dac}], 0x6420746f
        // 00405a91  c7855ce2ffff6f672121   mov     dword [ebp-0x1da4 {var_1da8}], 0x2121676f
        // choung dong looks like hot dog!!
        $insult_01 = { 63686f75 }
        $insult_02 = { 6e672064 }
        $insult_03 = { 6f6e6720 }
        $insult_04 = { 6c6f6f6b }
        $insult_05 = { 73206c69 }
        $insult_06 = { 6b652068 }
        $insult_07 = { 6f742064 }
        $insult_08 = { 6f672121 }

    condition:
        uint16(0) == 0x5a4d
        and filesize <= 100KB
        and (
            1 of ($mutex_*)
            or $empty_bins
            or all of ($insult_*)
        )
        and not (
            $primerose
            or any of ($decrypt_*)
        )
}
