rule TrapStealer
{
  meta:
    description = "Detect Trap Stealer"

  strings:
    $a = "detect_debugger_timing"

  condition:
    $a
}

rule RedTigerStealer
{
  meta:
    description = "Detect RedTiger Stealer"

  strings:
    $a = "RedTiger Ste4ler"

  condition:
    $a
}

rule BCStealer
{
  meta:
    description = "Detect BC Stealer"

  strings:
    $a = "blackcap"

  condition:
    $a
}

rule CStealer
{
  meta:
    description = "Detect CStealer"

  strings:
    $a = "cs.png"

  condition:
    $a
}

rule Pysilon
{
  meta:
    description = "Detect PySilon"

  strings:
    $pys1 = ".pysilon"
		$pys2 = "\\PySilon.key"
		$pys3 = "source_prepared"
    $uac_bypass = "resources.uac_bypass"
    $discord_token_grabber = "resources.discord_token_grabber"
  condition:
      ($pys1 or $pys2) or $pys3 or ($uac_bypass and $discord_token_grabber)
}

rule ExelaV2
{
  meta:
    description = "Detect ExelaV2"

  strings:
    $a = "cryptography.hazmat.primitives.ciphers"
    $b = "DecryptString"

  condition:
    all of them
}

rule Empyrean
{
  meta:
    description = "Detect Empyrean"

  strings:
    $a = "__CONFIG__"

  condition:
    $a
}

rule LunaGrabber
{
  meta:
    description = "Detect Luna Grabber"

  strings:
    $a = "tkcolorpickerr"

  condition:
    $a
}

rule HawkishEyes
{
  meta:
    description = "Detect Hawkish Eyes"

  strings:
    $a = "Hawkish-Eyes"

  condition:
    $a
}

rule NiceRAT
{
  meta:
    description = "Detect NiceRAT"

  strings:
    $a = "t.me/NiceRAT"

  condition:
    $a
}

rule PlainBlankGrabber
{
  meta:
    description = "Detect Plain BlankGrabber"

  strings:
    $ = /b+lank\.aes/

  condition:
    all of them
}
