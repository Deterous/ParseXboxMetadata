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
SS Hash: F18A4787
LBA Data Start: 198144
LBA Layerbreak: 1913775
LBA Data Final: 3629407
CPR_MAI Key: D2F5A6C7
enCrypted Challenge Responses: 23
Creation Timestamp: 2004-11-01 10:06:51607000
Authoring Timestamp: 2004-11-01 11:16:14991300
Certificate Timestamp: 2004-11-02 11:11:33000000
Mastering Timestamp: 2004-11-08 23:40:55041635
SS LBA Range #01: 368086-372181
SS LBA Range #02: 525408-529503
SS LBA Range #03: 681570-685665
SS LBA Range #04: 832282-836377
SS LBA Range #05: 988248-992343
SS LBA Range #06: 1140874-1144969
SS LBA Range #07: 1300696-1304791
SS LBA Range #08: 1840940-1845035
SS LBA Range #09: 2446418-2450513
SS LBA Range #10: 2605898-2609993
SS LBA Range #11: 2754620-2758715
SS LBA Range #12: 2913906-2918001
SS LBA Range #13: 3063402-3067497
SS LBA Range #14: 3225774-3229869
SS LBA Range #15: 3379016-3383111
SS LBA Range #16: 3534182-3538277
```
```
System: Xbox 360 (XGD2)
XGD2: Raw SS
SS Hash: DDEA754A
Redump SS Hash: EAFB630F
Fixed angles SS Hash: E993DA80
abgx360 filename: SS_92B2694A.bin
LBA Data Start: 129824
LBA Layerbreak: 1913759
LBA Data Final: 3697695
CPR_MAI Key: 0949B873
Media ID: 9D3070753DEB6B5E68B44018-2BC527C6
Authoring Timestamp: 2009-09-28 00:00:00000000
Mastering Timestamp: 2009-10-06 02:36:07250000
SS LBA Range #01: 108976-113071
SS LBA Range #04: 3719856-3723951
```
```
System: Xbox 360 (XGD2)
XGD2: Cleaned Kreon-style SS (Redump hash)
SS Hash: A1920A65
Redump SS Hash: A1920A65
Fixed angles SS Hash: A2FAB3EA
abgx360 filename: SS_1204560D.bin
LBA Data Start: 129824
LBA Layerbreak: 1913759
LBA Data Final: 3697695
CPR_MAI Key: EFF954F7
Media ID: 0D50D93F4FF1B1D7EF914710-331A081B
Authoring Timestamp: 2008-06-03 00:00:00000000
Mastering Timestamp: 2008-06-22 02:49:57406250
SS LBA Range #01: 108976-113071
SS LBA Range #04: 3719856-3723951
```
