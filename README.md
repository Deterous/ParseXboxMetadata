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

---

# ParseDMI

`python ParseDMI.py <filename>`

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
