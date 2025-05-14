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
SS Hash: 16177486
LBA Data Start: 198144
LBA Layerbreak: 1913775
LBA Data Final: 3629407
CPR_MAI Key: 9D044049
enCrypted Challenge Responses: 23
Creation Timestamp: 2002-04-09 11:33:00133000
Authoring Timestamp: 2002-04-10 11:01:30494915
Mastering Timestamp: 2002-04-24 08:55:43355312
SS LBA Range #01: 288672-292767
SS LBA Range #02: 463850-467945
SS LBA Range #03: 678852-682947
SS LBA Range #04: 837422-841517
SS LBA Range #05: 991684-995779
SS LBA Range #06: 1259320-1263415
SS LBA Range #07: 1450430-1454525
SS LBA Range #08: 1718748-1722843
SS LBA Range #09: 1980892-1984987
SS LBA Range #10: 2292000-2296095
SS LBA Range #11: 2448750-2452845
SS LBA Range #12: 2756682-2760777
SS LBA Range #13: 2908800-2912895
SS LBA Range #14: 3066474-3070569
SS LBA Range #15: 3224938-3229033
SS LBA Range #16: 3454360-3458455
```
```
System: Xbox 360 (XGD2)
XGD2: Clean
SS Hash: C87BA80B
Cleaned SS Hash: C87BA80B
abgx360 SS Hash: B36F0399
LBA Data Start: 129824
LBA Layerbreak: 1913759
LBA Data Final: 3697695
CPR_MAI Key: 004C68DD
Media ID: 90267DFDD6CF869DC8D43FA1-13CB39C4
Authoring Timestamp: 2011-02-04 00:00:00000000
Mastering Timestamp: 2011-02-15 06:58:37000000
SS LBA Range #01: 108976-113071
SS LBA Range #04: 3719872-3723967
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
CPR_MAI Key: 66D2EDDB
Media ID: D664F5CB98F39197BB933A8C-2F510839
Authoring Timestamp: 2011-07-18 00:00:00000000
Mastering Timestamp: 2011-08-04 15:43:59234375
SS LBA Range #01: 12544-16639
SS LBA Range #04: 4246304-4250399
```
