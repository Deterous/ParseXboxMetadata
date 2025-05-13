This repository has scripts that read, validate and parse metadata from the following files:
- XBE (XBox eXecutable), Xbox only
    - XBE files (`filename.xbe`) can be extracted from Xbox game partitions, using programs such as [extract-xiso](https://github.com/XboxDev/extract-xiso) or [NKit2](https://github.com/Nanook/NKit)
- DMI (Disc Manufacturing Information sector), Xbox and Xbox 360
    - DMI files (e.g. `DMI.bin` or `filename.dmi`) can be obtained from the SCSI command READ DISC STRUCTURE using dumping programs such as [Redumper](https://github.com/superg/redumper), [DiscImageCreator](https://github.com/saramibreak/DiscImageCreator/), and XboxBackupCreator
- SS (Security Sector), Xbox and Xbox 360
    - SS files (e.g. `SS.bin` or `filename.ss`) can be obtained from specific disc drives using dumping programs such as [Redumper](https://github.com/superg/redumper), [DiscImageCreator](https://github.com/saramibreak/DiscImageCreator/), and XboxBackupCreator

TODO:
- XEX (Xbox 360 executable file)

# ParseXBE

`python ParseXBE.py <filename.xbe>`

Parses Xbox XBE files for their useful metadata, e.g.

```
XBE Timestamp: 2003-12-19 17:46:38 UTC
Certificate Timestamp: 2005-04-11 19:24:08 UTC
Title ID: MS-133
Title Name: CDX
Alternate Title IDs:
    MS-109
Allowed Media: 0x202
Game Region: 0x7
Game Ratings: 0x2
Disc Number: 0
Certificate Version: 2
```

# ParseDMI

`python ParseDMI.py <filename> [-v, --verbose]`

Parses Xbox and Xbox360 DMI sector for its useful metadata, e.g.

```
System: Xbox (XGD1)
XMID: MS13302W
DMI Datetime: 2005-04-11 19:23:43864302
```
```
System: Xbox 360 (XGD2/3)
DMI Date: 2012-09-24
XOR Key: Retail
Media ID: 4F24FBB52FD1F0B37DC7ACDE-4CB283E9
XeMID: MS232924W0AF11
PFI CRC: 26AF4C58
```

# ParseSS

`python ParseSS.py <filename> [-v, --verbose]`

Parse Xbox and Xbox360 SS sector for its useful metadata, e.g.

```
System: Xbox (XGD1)
SS Hash: 5A53D4AA
LBA Data Start: 198144
LBA Layerbreak: 1913775
LBA Data Final: 3629407
CPR_MAI Key: CDE0042B
enCrypted Challenge Responses: 23
Creation Timestamp: 2005-03-21 18:49:53238000
Authoring Timestamp: 2005-03-21 20:35:35535062
Certificate Timestamp: 2005-03-22 20:34:15000000
Mastering Timestamp: 2005-03-26 23:22:58441377
SS LBA Range #01: 291442-295537
SS LBA Range #02: 446806-450901
SS LBA Range #03: 601146-605241
SS LBA Range #04: 754590-758685
SS LBA Range #05: 908806-912901
SS LBA Range #06: 1064214-1068309
SS LBA Range #07: 1299950-1304045
SS LBA Range #08: 1607354-1611449
SS LBA Range #09: 1983556-1987651
SS LBA Range #10: 2295734-2299829
SS LBA Range #11: 2443916-2448011
SS LBA Range #12: 2676466-2680561
SS LBA Range #13: 2838690-2842785
SS LBA Range #14: 3145710-3149805
SS LBA Range #15: 3296646-3300741
SS LBA Range #16: 3451356-3455451
```
```
System: Xbox 360 (XGD2)
XGD2: Not Clean
SS Hash: 852E424B
Cleaned SS Hash: 6F6547A9
abgx360 SS Hash: 7215B6F6
LBA Data Start: 129824
LBA Layerbreak: 1913759
LBA Data Final: 3697695
SHA-1 (Unknown): 00A5587F7EF0FAC4486AA56D8D950364C07BDC80
Challenge Responses: 8
CPR_MAI Key: EE62F127
enCrypted Challenge Responses: 28
Media ID: C71F0B82F430C7181FF23DE2-04A0608E
Authoring Timestamp: 2008-09-30 00:00:00000000
Mastering Timestamp: 2008-10-12 04:17:27015625
SS LBA Range #01: 108976-113071
SS LBA Range #04: 3719856-3723951
```
```
System: Xbox 360 (XGD3)
XGD3 with SSv2
XGD3 SSv2: Clean
SS Hash: 606D4E4C
Cleaned SS Hash: 606D4E4C
abgx360 SS Hash: 5D7D8521
LBA Data Start: 16640
LBA Layerbreak: 2133519
LBA Data Final: 4246303
Unknown1 Value: 003A6570
SHA-1 (Unknown): 00AF0C15426AC678C820EDDF2AF1F12C7E0DA243
Challenge Responses: 23
CPR_MAI Key: 66D2EDDB
enCrypted Challenge Responses: 28
Media ID: D664F5CB98F39197BB933A8C-2F510839
Authoring Timestamp: 2011-07-18 00:00:00000000
Mastering Timestamp: 2011-08-04 15:43:59234375
SS LBA Range #01: 12544-16639
SS LBA Range #04: 4246304-4250399
```
