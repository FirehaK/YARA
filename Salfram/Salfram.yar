rule Salfram : crypter salfram
{
    meta:
        author      = "@_FirehaK <yara@firehak.com>"
        date        = "2020-11-05"
        description = "Detects a modifed DOS header used by Salfram"
        hash        = "2b0d228cf2c9370340a23782fd926e234ed8c41232cf9f6a94b3e74e3ea9fc42"
        modified    = "2020-11-05"
        reference   = "https://blog.talosintelligence.com/2020/09/salfram-robbing-place-without-removing.html"
        tlp         = "WHITE"
    
    strings:
        $salfram = "This Salfram cannot be run in DOS mode." ascii
	
    condition:
		$salfram
}
