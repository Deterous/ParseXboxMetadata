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
XMID: MS10010W
DMI Timestamp: 2004-09-30 17:38:25674749
```
```
System: Xbox 360 (XGD2/3)
DMI Timestamp: 2010-10-18 00:00:00000000
XOR Key: Retail
Media ID:  33EAD0291EE79C1DFE5B6B3F638DA23A
XeMID: AV207903J0X11
PFI CRC: 05C6C409
Xbox Signature: Valid
```
