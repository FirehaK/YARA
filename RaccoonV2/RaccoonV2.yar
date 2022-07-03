rule RaccoonV2 : loader stealer
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2022-06-04"
        description = "This rule detects Raccoon Stealer version 2.0 (called Recordbreaker before attribution). It has been spotted spreading through fake software cracks and keygens as far back as April 2022."
        modified    = "2022-06-30"
        reference   = "https://www.zerofox.com/blog/brief-raccoon-stealer-version-2-0/"
        tlp         = "WHITE"

    strings:
        $winapi_imports_01 = { 57 68???????? 50 ffd6 68 ???????? a3 }
        $winapi_imports_02 = { ffd0 8b0d???????? 8bd8 68???????? ffd1 8b0d???????? 68???????? 8945?? ffd1 }
        $winapi_imports_03 = { ff15???????? 68???????? ff75?? ffd6 8b75?? 68???????? 56 a3???????? ffd0 }
        $decrypt_strings_01 = { b9???????? e8???????? bf???????? 8d4d?? 57 51 be???????? 50 8bce e8???????? 8d55?? a3 }
        $decrypt_strings_02 = { b9???????? e8???????? 57 8d4d?? 51 50 8bce e8???????? 8d55?? a3 }
        $process_c2_string = { 50 6a40 ffd6 8b0d???????? 8bf0 68???????? 57 33db ffd1 85c0 74?? 8a07 3c20 74?? 8bce 2bcf 880439 43 47 8a07 3c20 75 }
        $external_imports = { ff35???????? a1???????? 56 ffd0 ff35???????? a3 }
        $unknown = { 85c9 74?? 0fb73c30 6685ff 74?? 66893e 83c602 49 83ea01 75?? 5f 33c9 b87a000780 }

    condition:
        uint16(0) == 0x5a4d
        and all of them
}
