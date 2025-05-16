import sys
import datetime
import hashlib
import zlib
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("The 'cryptography' module is needed to decrypt the Challenge Response Table.")
    print("Please install 'cryptography' using pip:")
    print("python -m pip install cryptography")
    raise


def parse_ccrt(data, xgd, cpr_mai, verbose):
    if xgd == 1:
        enc_response_count = 0
        for i, offset in enumerate(range(0x302, 0x3FF, 11), start=1):
            hex_str = ''.join(f'{b:02X}' for b in data[offset:offset + 11])
            if hex_str != "0000000000000000000000":
                enc_response_count = enc_response_count + 1
        print(f"enCrypted Challenge Responses: {enc_response_count}")
    else:
        return
    
    hash_input = data[1183:1183+44]
    sha1_hash = hashlib.sha1(hash_input).digest()
    key = sha1_hash[:7]
    
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    x = 0
    y = 0
    for pos in range(770, 770+253):
        x = (x + 1) % 256
        y = (y + S[x]) % 256
        S[x], S[y] = S[y], S[x]
        out.append(data[pos] ^ S[(S[x] + S[y]) % 256])
    
    valid_challenge_found = False
    for i in range(0, len(out), 11):
        #print(f"{int.from_bytes(bytearray(out[i:i+11]), 'big'):022X}")
        if out[i] == 0x01:
            if not valid_challenge_found:
                if verbose:
                    print("Valid Decrypted Challenge Responses:")
                challenge_value = out[i+2:i+2+4]
                valid_challenge_found = True
            else:
                if bytes(challenge_value) != cpr_mai:
                    print("[WARNING] Invalid Challenge Value")
            if verbose:
                print(f"Challenge ID: {out[i+1]:02X}, Value: {int.from_bytes(bytearray(out[i+2:i+2+4]), 'big'):04X}, Response Modifier: {out[i+6]:02X}, Response: {int.from_bytes(bytearray(out[i+7:i+7+4]), 'big'):04X}")
        elif out[i] != 0x02 and out[i] != 0x03 and (out[i] & 0xF0) != 0xF0:
            print("[WARNING] Unexpected Challenge ID")
    if not valid_challenge_found:
        print("[WARNING] No valid challenge entries")
    
    for i in range(0, 23*9, 9):
        id_match = 0
        for j in range(0, len(out), 11):
            if data[0x661+i+1] == out[j+1]:
                id_match = id_match + 1
        if id_match == 0:
            print("[WARNING] No matching response ID")
        elif id_match > 1:
            print("[WARNING] More than one matching response ID")
        if i >= 16*9 and data[0x661+i] != 0x00 and (data[0x661+i] & 0xF0) != 0xF0:
            print("[WARNING] Unexpected Challenge ID")
        #print(f"{int.from_bytes(data[0x661+i:0x661+i+3], 'big'):06X} {int.from_bytes(data[0x661+i+3:0x661+i+6], 'big'):06X} {int.from_bytes(data[0x661+i+6:0x661+i+9], 'big'):06X}")


def parse_ccrt2(data, xgd, cpr_mai, verbose):
    if xgd == 1:
        return
    elif xgd == 2:
        offset = 0x200
    elif xgd >= 3:
        offset = 0x20
    
    key = bytes([0xD1, 0xE3, 0xB3, 0x3A, 0x6C, 0x1E, 0xF7, 0x70, 0x5F, 0x6D, 0xE9, 0x3B, 0xB6, 0xC0, 0xDC, 0x71])
    iv = bytearray(16)
    dcrt = bytearray(252)
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    for i in range(15):
        ct = bytes(data[0x304+i*16:0x304+(i+1)*16])
        pt = bytearray(cipher.update(ct))
        for j in range(16):
            pt[j] ^= iv[j]
        iv[:] = ct
        dcrt[i*16 : (i+1)*16] = pt
        
    enc_response_count = 0
    for i in range(0x304, 0x400, 12):
        hex_str = ''.join(f'{b:02X}' for b in data[i:i+12])
        if hex_str != "000000000000000000000000":
            enc_response_count = enc_response_count + 1
    
    if enc_response_count != 21:
        print("[WARNING] Unexpected encrypted challenge count: {enc_response_count}")
    
    if verbose:
        print(f"Decrypted Challenges: {enc_response_count}")
        print(f"{'CT':<4}{'CID':<4}{'Tol':<4}{'Type':<6}{'Challenge':<11}{'Response':<10}{'Angle':<8}")
    
    dcrtentry = []
    CT01_conflict = False
    CT01_count = 0
    CT01_firstCD = bytearray(4)
    for i in range(enc_response_count):
        entry = {
            "CT": dcrt[i*12],  # Challenge Type
            "CID": dcrt[i*12+1],  # Challenge ID
            "Tolerance": dcrt[i*12+2],
            "Type": dcrt[i*12+3],
            "CD": dcrt[i*12+4:i*12+8],
            "Response": dcrt[i*12+8:i*12+12],
            "angle": (dcrt[i*12+10] << 8) | dcrt[i*12+11],
        }
        dcrtentry.append(entry)
        
        if entry["CT"] == 0x01:
            CT01_count += 1
            if CT01_count == 1:
                CT01_firstCD[:] = entry["CD"]
            elif CT01_firstCD != entry["CD"]:
                print("[WARNING] CT01 conflict")
        
        if entry['angle'] == 0 or entry['angle'] > 360:
            entry['angle'] = ''
        else:
            entry['angle'] = f"{entry['angle']}°"
        if verbose:
            print(f"{entry['CT']:02X}  {entry['CID']:02X}  {entry['Tolerance']:02X}   {entry['Type']:02X}   "
              f"{entry['CD'][0]:02X}{entry['CD'][1]:02X}{entry['CD'][2]:02X}{entry['CD'][3]:02X}   "
              f"{entry['Response'][0]:02X}{entry['Response'][1]:02X}{entry['Response'][2]:02X}{entry['Response'][3]:02X}   "
              f"{entry['angle']:<7}")
    if not CT01_conflict and CT01_firstCD != cpr_mai:
        print(f"[WARNING] CPR_MAI mismatch, CCRT contains: {int.from_bytes(CT01_firstCD, 'big'):04X}")
    
    response_count = 0
    for i in range(offset, offset + 0xCF, 9):
        hex_str = ''.join(f'{b:02X}' for b in data[i:i+9])
        if hex_str != "000000000000000000":
            response_count = response_count + 1
    
    if verbose:
        print(f"Challenge Responses: {response_count}")
        print(f"{'RT':<4}{'CID':<4}{'Mod':<5}{'Data':<15}{'Challenge':<11}{'Response':<11}")
    
    rtentry = []
    for i in range(response_count):
        entry = {
            "RT": data[0x730+i*9],  # Response Type
            "CID": data[0x730+i*9+1],  # Challenge ID
            "Mod": data[0x730+i*9+2],
            "Data": data[0x730+i*9+3:0x730+i*9+9],  # incl SS ranges
            "CD": data[offset+i*9:offset+i*9+4],
            "Response": data[offset+i*9+4:offset+i*9+9],
            "angle": (data[offset+i*9+5] << 8) | data[offset+i*9+5],
            "angle2": (data[offset+i*9+8] << 8) | data[offset+i*9+7],
        }
        rtentry.append(entry)
        
        if verbose:
            print(f"{entry['RT']:02X}  {entry['CID']:02X}  {entry['Mod']:02X}   "
              f"{entry['Data'][0]:02X}{entry['Data'][1]:02X}{entry['Data'][2]:02X}{entry['Data'][3]:02X}{entry['Data'][4]:02X}{entry['Data'][5]:02X}   "
              f"{entry['CD'][0]:02X}{entry['CD'][1]:02X}{entry['CD'][2]:02X}{entry['CD'][3]:02X}   "
              f"{entry['Response'][0]:02X}{entry['Response'][1]:02X}{entry['Response'][2]:02X}{entry['Response'][3]:02X}{entry['Response'][4]:02X}   ")
    
    for entry in rtentry:
        for crt in dcrtentry:
            if crt['CID'] == entry['CID']:
                if (crt['CT'] == 0x15 and entry['RT'] != 0x01) or (crt['CT'] == 0x14 and entry['RT'] != 0x03) or (crt['CT'] == 0x25 and entry['RT'] != 0x05) or (crt['CT'] == 0x24 and entry['RT'] != 0x07):
                    print("[WARNING] Mismatched CT/RT")
                if crt['CT'] != 0x24 and crt['CT'] != 0x25:
                    if crt['CD'] != entry['CD']:
                        print(f"[WARNING] Mismatched CD for CID {entry['CID']:02X}")
                    if crt['Response'] != entry['Response'][:-1]:
                        print(f"[WARNING] Mismatched Response for CID {entry['CID']:02X}")
                    break


def parse_pfi(data, xgd):
    version = data[0] & 0xF
    book_type = (data[0] >> 4) & 0xF
    max_rate = data[1] & 0xF
    disc_size = (data[1] >> 4) & 0xF
    layer_type = data[2] & 0xF
    path = (data[2] >> 4) & 1
    layer_count1 = (data[2] >> 5) & 1
    layer_count2 = (data[2] >> 6) & 1
    reserved = (data[2] >> 7) & 1
    track_density = data[3] & 0xF
    linear_density = (data[3] >> 4) & 0xF
    if version != 0x1:
        print(f"[WARNING] Unexpected PFI version: 0x{version:02X}")
    if(xgd   == 1 and book_type != 0xD) or (xgd != 1 and book_type != 0xE):
        print(f"[WARNING] Unexpected PFI book type: 0x{book_type:02X}")
    if max_rate != 0xF:
        print(f"[WARNING] Unexpected PFI maximum rate: 0x{max_rate:02X}")
    if disc_size != 0x0:
        print(f"[WARNING] Unexpected PFI disc size: 0x{disc_size:02X}")
    if layer_type != 0x1:
        print(f"[WARNING] Unexpected PFI layer type: 0x{layer_type:02X}")
    if path != 0x1:
        print(f"[WARNING] Unexpected PFI path bit unset")
    if layer_count1 != 0x1 or layer_count2 != 0x0:
        print(f"[WARNING] Unexpected PFI layer count: 0b{layer_count2}{layer_count1}")
    if reserved != 0x0:
        print(f"[WARNING] Unexpected PFI reserved bit set")
    if track_density != 0x0:
        print(f"[WARNING] Unexpected PFI track density: 0x{track_density:02X}")
    if linear_density != 0x1:
        print(f"[WARNING] Unexpected PFI linear density: 0x{linear_density:02X}")
    
    psn_start = 196608
    lba_start = int.from_bytes(data[4:8], byteorder='big') - psn_start
    layer0_end = int.from_bytes(data[12:16], byteorder='big') - psn_start
    layer1_size = int.from_bytes(data[8:12], byteorder='big') - (~(int.from_bytes(data[12:16], byteorder='big') + 1) & 0xFFFFFF)
    print(f"LBA Data Start: {lba_start}")
    print(f"LBA Layerbreak: {layer0_end}")
    print(f"LBA Data Final: {layer0_end + layer1_size}")
    
    bca_reserved = data[0x10] & 0x7F
    bca = (data[0x10] >> 7) & 1
    if bca_reserved != 0x00:
        print(f"[WARNING] Unexpected reserved byte set: 0x{bca_reserved:02X}")
    if bca != 0x0:
        print(f"[WARNING] Unexpected BCA bit set")


def filetime(data):
    filetime = int.from_bytes(data, "little")
    if filetime < 0x19DB1DED53E8000:
        return ""
    time = divmod(filetime - 0x19DB1DED53E8000, 10000000)
    time = datetime.datetime.fromtimestamp(time[0], datetime.UTC).replace(microsecond=time[1] // 10)
    return f"{time.strftime(f"%Y-%m-%d %H:%M:%S%f")}"


def time_t(data):
    timet = int.from_bytes(data, 'little')
    time = datetime.datetime.fromtimestamp(timet, datetime.UTC)
    return f"{time.strftime(f"%Y-%m-%d %H:%M:%S%f")}"


def parse_ss(data, xgd, verbose):
    if xgd == 2:
        if data[0x100:0x104] != bytes([0x00, 0x00, 0x00, 0x30]):
            print(f"Unexpected Unknown1 Value: {int.from_bytes(data[0x100:0x104], 'big'):08X}")
        if data[0x104:0x108] != bytes([0x00, 0x00, 0x06, 0xE0]):
            print(f"Unexpected Unknown2 Value: {int.from_bytes(data[0x104:0x108], 'big'):08X}")
    
    if xgd > 2:
        print(f"Unknown1 Value: {int.from_bytes(data[0x100:0x104], 'big'):08X}")
        if data[0x104:0x108] != bytes([0x00, 0x00, 0x18, 0x80]):
            print(f"[WARNING] Unexpected Unknown2 Value: {int.from_bytes(data[0x104:0x108], 'big'):08X}")
    
    if xgd > 1 and verbose:
        print(f"SHA-1 (Unknown): {int.from_bytes(data[0x108:0x11B], 'big'):040X}")
    
    if xgd == 4:
        cpr_mai = data[0x0F0:0x0F4]
    else:
        cpr_mai = data[0x2D0:0x2D4]
    print(f"CPR_MAI Key: {int.from_bytes(cpr_mai, byteorder='big'):08X}")
    
    if (xgd == 1 and data[0x300] != 1) or (xgd > 1 and data[0x300] != 2):
        print(f"Unexpected CCRT Version: 0x{data[0x300]:02X}")
    if (xgd == 1 and data[0x301] != 23) or (xgd > 1 and data[0x301] != 21):
        print(f"Unexpected CCRT Count: 0x{data[0x301]:02X}")
    
    if xgd == 1:        
        parse_ccrt(data, xgd, cpr_mai, verbose)
        
        creation_time = filetime(data[0x41F:0x427])
        if creation_time == "":
            print(f"[WARNING] Invalid Creation FILETIME: {int.from_bytes(data[0x41F:0x427], 'big'):016X}")
        else:
            print(f"Creation Timestamp: {creation_time}")
        
        if verbose:
            print(f"Certificate GUID: {int.from_bytes(data[0x427:0x437], 'big'):016X}")
            print(f"Authoring GUID: {int.from_bytes(data[0x43B:0x44B], 'big'):016X}")
    elif xgd > 1:        
        parse_ccrt2(data, xgd, cpr_mai, verbose)
        
        media_id = data[0x460:0x470]
        media_id_str = ''.join(f"{b:02X}" for b in media_id)
        print(f"Media ID: {media_id_str[:-8] + '-' + media_id_str[-8:]}")
        
        if data[0x49E] != 0x04:
            print(f"[WARNING] Unexpected value at 0x49E: 0x{data[0x49E]:02X}")
    
    authoring_time = filetime(data[0x49F:0x4A7])
    if authoring_time == "":
        print(f"[WARNING] Invalid Authoring FILETIME: {int.from_bytes(data[0x49F:0x4A7], 'big'):016X}")
    else:
        print(f"Authoring Timestamp: {authoring_time}")
    
    if xgd == 1:
        if data[0x4A7:0x4AB] == b'\x00' * 4:
            if verbose:
                print("Zeroed Certificate Timestamp")
        else:
            cert_time = time_t(data[0x4A7:0x4AB])
            print(f"Certificate Timestamp: {cert_time}")
    
    if verbose:
        print(f"Unknown GUID: {int.from_bytes(data[0x4BB:0x4CB], 'big'):016X}")
        print(f"SS SHA-1 A: {int.from_bytes(data[0x4CB:0x4DF], 'big'):016X}")
        print(f"SS Signature A: {int.from_bytes(data[0x4CB:0x4DF], 'big'):016X}")
    
    mastering_time = filetime(data[0x5DF:0x5E7])
    if mastering_time == "":
        print(f"[WARNING] Invalid Mastering FILETIME: {int.from_bytes(data[0x5DF:0x5E7], 'big'):016X}")
    else:
        print(f"Mastering Timestamp: {mastering_time}")
    
    if data[0x5E7:0x5EB] != b'\x00' * 4:
        cert_time = time_t(data[0x5E7:0x5EB])
        print(f"[WARNING] Unexpected Mastering Timestamp: {cert_time}")
    
    if xgd == 1 and data[0x5FA] != 0xFF: 
        if data[0x5FA] == 0x02:
            print("XGD1 is late pressing, extra data is in DMI")
        else:
            print(f"[WARNING] Unexpected value at 0x5FA: {data[0x5FA]:02X}")
    elif xgd > 1 and data[0x5FA] != 0x02:
        print(f"[WARNING] Unexpected value at 0x5FA: {data[0x5FA]:02X}")
    
    if verbose:
        print(f"Mastering GUID: {int.from_bytes(data[0x5FB:0x60B], 'big'):016X}")
        print(f"SS SHA-1 B: {int.from_bytes(data[0x60B:0x61F], 'big'):016X}")
        print(f"SS Signature B: {int.from_bytes(data[0x61F:0x65F], 'big'):016X}")
    
    if xgd == 1 and data[0x65F] != 0x01:
        if data[0x65F] != 0x01:
            print("XGD1 with SS Version 2")
        else:
            print(f"[WARNING] Unexpected value at 0x65F: {data[0x65F]:02X}")
    elif xgd > 1 and data[0x65F] != 0x02:
        print(f"[WARNING] Unexpected value at 0x65F: {data[0x65F]:02X}")
    
    layer1_offset = (int.from_bytes(data[12:16], byteorder='big') * 2) - 196608 + 1
    for i, offset in enumerate(range(0x661, 0x72E, 9), start=1):
        range_start = int.from_bytes(data[offset+3:offset+6], 'big')
        range_end = int.from_bytes(data[offset+6:offset+9], 'big')
        if not verbose and (xgd == 1 and i < 9) or (xgd > 1 and i == 1):
            print(f"SS LBA Range #{i:02}: {range_start - 196608}-{range_end - 196608}")
        elif not verbose and (xgd == 1 and i < 17) or (xgd > 1 and i == 4):
            print(f"SS LBA Range #{i:02}: {layer1_offset - (~range_start & 0xFFFFFF)}-{layer1_offset - (~range_end & 0xFFFFFF)}")
    if verbose:
        for i, offset in enumerate(range(0x661, 0x72E, 9), start=1):
            range_start = int.from_bytes(data[offset+3:offset+6], 'big')
            range_end = int.from_bytes(data[offset+6:offset+9], 'big')
            print(f"SS PSN Range #{i:02}: {range_start:06X}-{range_end:06X}")
    
    if data[0x661:0x730] != data[0x730:0x7FF]:
        print("[WARNING] Duplicated SS range does not match")


def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("Usage: python ParseSS.py <filename> [-v, --verbose]")
        return
    
    verbose = False
    filename = sys.argv[1]
    if len(sys.argv) == 3:
        if filename == "-v" or filename =="--verbose":
            verbose = True
            filename = sys.argv[2]
        elif sys.argv[2] == "-v" or sys.argv[2] == "--verbose":
            verbose = True
    
    with open(filename, 'rb') as f:
        data = f.read(2048)
        if len(data) < 2048:
            print("[ERROR] Not a valid SS: <2048 bytes")
            return
        
        xgd = 0
        layer0_end = data[13:16]
        if layer0_end == bytes([0x20, 0x33, 0xAF]):
            xgd = 1
        elif layer0_end == bytes([0x20, 0x33, 0x9F]):
            xgd = 2
        elif layer0_end == bytes([0x23, 0x8E, 0x0F]):
            xgd = 3
        else:
            print(f"[WARNING] Unexpected PSN Layer 0 End: {int.from_bytes(layer0_end, 'big'):04X}")
        
        if data[0x4BA] == 0x01:
            if xgd == 0:
                xgd = 1
            elif xgd != 1:
                print(f"[WARNING] XGD1 but value at 0x4BA is: {data[0x4BA]}")
        elif data[0x4BA] == 0x02:
            if xgd == 0:
                xgd = 2.5
            elif xgd != 2 and xgd != 3:
                print(f"[WARNING] XGD{xgd} but value at 0x4BA is: {data[0x4BA]}")
        else:
            print(f"[WARNING] Unexpected value at 0x4BA: {data[0x4BA]}")
        
        if xgd == 1:
            print("System: Xbox (XGD1)")
        elif xgd == 2:
            print("System: Xbox 360 (XGD2)")
        elif xgd == 2.5:
            print("System: Xbox 360 (XGD2 ?)")
            xgd = 2
        elif xgd == 3:
            print("System: Xbox 360 (XGD3)")
        else:
            print("[ERROR] Could not detect XGD version")
            return
        
        if data[32:104] != b'\x00' * 72:
            if xgd == 3:
                xgd = 4
                print("XGD3 with SSv2")
            else:
                print(f"[WARNING] XGD{xgd} SS with non-zero data in SSv2 area")
        elif xgd == 3:
            print("XGD3 with SSv1 (bad)")
        
        clean_kreon_ss = bytearray(data)
        abgx_ss = bytearray(data)
        clean_0800_ss = bytearray(data)
        if xgd == 2:
            for i in range(0x200, 0x300):
                abgx_ss[i] = 0xFF
            if abgx_ss == bytearray(data):
                print("[WARNING] XGD2 SS matches abgx360 internal hash, bad angles")
        elif xgd == 4:
            for i in range(0x20, 0xF4):
                abgx_ss[i] = 0xFF
            if abgx_ss == bytearray(data):
                print("[WARNING] XGD3 SS matches abgx360 internal hash, bad angles")
        
        if xgd == 2:
            if data[552] == 0x01 and data[553] == 0x00 and data[555] == 0x00 and data[556] == 0x00 and data[561] == 0x5B and data[562] == 0x00 and data[564] == 0x00 and data[565] == 0x00 and data[570] == 0xB5 and data[571] == 0x00 and data[573] == 0x00 and data[574] == 0x00 and data[579] == 0x0F and data[580] == 0x01 and data[582] == 0x00 and data[583] == 0x00:
                print("XGD2: Cleaned Kreon-style SS (Redump hash)")
                clean_0800_ss[552] = 0x01
                clean_0800_ss[553] = 0x00
                clean_0800_ss[555] = 0x01
                clean_0800_ss[556] = 0x00
                clean_0800_ss[561] = 0x5B
                clean_0800_ss[562] = 0x00
                clean_0800_ss[564] = 0x5B
                clean_0800_ss[565] = 0x00
                clean_0800_ss[570] = 0xB5
                clean_0800_ss[571] = 0x00
                clean_0800_ss[573] = 0xB5
                clean_0800_ss[574] = 0x00
                clean_0800_ss[579] = 0x0F
                clean_0800_ss[580] = 0x01
                clean_0800_ss[582] = 0x0F
                clean_0800_ss[583] = 0x01
            elif data[552] == 0x01 and data[553] == 0x00 and data[555] == 0x01 and data[556] == 0x00 and data[561] == 0x5B and data[562] == 0x00 and data[564] == 0x5B and data[565] == 0x00 and data[570] == 0xB5 and data[571] == 0x00 and data[573] == 0xB5 and data[574] == 0x00 and data[579] == 0x0F and data[580] == 0x01 and data[582] == 0x0F and data[583] == 0x01:
                print("XGD2: Cleaned 0800-style SS")
                clean_kreon_ss[552] = 0x01
                clean_kreon_ss[553] = 0x00
                clean_kreon_ss[555] = 0x00
                clean_kreon_ss[556] = 0x00
                clean_kreon_ss[561] = 0x5B
                clean_kreon_ss[562] = 0x00
                clean_kreon_ss[564] = 0x00
                clean_kreon_ss[565] = 0x00
                clean_kreon_ss[570] = 0xB5
                clean_kreon_ss[571] = 0x00
                clean_kreon_ss[573] = 0x00
                clean_kreon_ss[574] = 0x00
                clean_kreon_ss[579] = 0x0F
                clean_kreon_ss[580] = 0x01
                clean_kreon_ss[582] = 0x00
                clean_kreon_ss[583] = 0x00
            else:
                print("XGD2: Raw SS")
                clean_kreon_ss[552] = 0x01
                clean_kreon_ss[553] = 0x00
                clean_kreon_ss[555] = 0x00
                clean_kreon_ss[556] = 0x00
                clean_kreon_ss[561] = 0x5B
                clean_kreon_ss[562] = 0x00
                clean_kreon_ss[564] = 0x00
                clean_kreon_ss[565] = 0x00
                clean_kreon_ss[570] = 0xB5
                clean_kreon_ss[571] = 0x00
                clean_kreon_ss[573] = 0x00
                clean_kreon_ss[574] = 0x00
                clean_kreon_ss[579] = 0x0F
                clean_kreon_ss[580] = 0x01
                clean_kreon_ss[582] = 0x00
                clean_kreon_ss[583] = 0x00
                clean_0800_ss[552] = 0x01
                clean_0800_ss[553] = 0x00
                clean_0800_ss[555] = 0x01
                clean_0800_ss[556] = 0x00
                clean_0800_ss[561] = 0x5B
                clean_0800_ss[562] = 0x00
                clean_0800_ss[564] = 0x5B
                clean_0800_ss[565] = 0x00
                clean_0800_ss[570] = 0xB5
                clean_0800_ss[571] = 0x00
                clean_0800_ss[573] = 0xB5
                clean_0800_ss[574] = 0x00
                clean_0800_ss[579] = 0x0F
                clean_0800_ss[580] = 0x01
                clean_0800_ss[582] = 0x0F
                clean_0800_ss[583] = 0x01
        elif xgd == 3:
            if data[552] == 0x01 and data[553] == 0x00 and data[561] == 0x5B and data[562] == 0x00 and data[570] == 0xB5 and data[571] == 0x00 and data[579] == 0x0F and data[580] == 0x00:
                print("XGD3 SSv1: Cleaned Kreon-style (Redump hash)")
                clean_kreon_ss[552] = 0x01
                clean_kreon_ss[553] = 0x00
                clean_kreon_ss[561] = 0x5B
                clean_kreon_ss[562] = 0x00
                clean_kreon_ss[570] = 0xB5
                clean_kreon_ss[571] = 0x00
                clean_kreon_ss[579] = 0x0F
                clean_kreon_ss[580] = 0x00
            else:
                print("XGD3 SSv1: Raw SS")
                clean_kreon_ss[552] = 0x01
                clean_kreon_ss[553] = 0x00
                clean_kreon_ss[561] = 0x5B
                clean_kreon_ss[562] = 0x00
                clean_kreon_ss[570] = 0xB5
                clean_kreon_ss[571] = 0x00
                clean_kreon_ss[579] = 0x0F
                clean_kreon_ss[580] = 0x00
        elif xgd == 4:
            if data[72] == 0x01 and data[73] == 0x00 and data[75] == 0x01 and data[76] == 0x00 and data[81] == 0x5B and data[82] == 0x00 and data[84] == 0x5B and data[85] == 0x00 and data[90] == 0xB5 and data[91] == 0x00 and data[93] == 0xB5 and data[94] == 0x00 and data[99] == 0x0F and data[100] == 0x01 and data[102] == 0x0F and data[103] == 0x01:
                print("XGD3 SSv2: Cleaned SS (Redump hash)")
            else:
                print("XGD3 SSv2: Raw SS")
                clean_kreon_ss[72] = 0x01
                clean_kreon_ss[73] = 0x00
                clean_kreon_ss[75] = 0x01
                clean_kreon_ss[76] = 0x00
                clean_kreon_ss[81] = 0x5B
                clean_kreon_ss[82] = 0x00
                clean_kreon_ss[84] = 0x5B
                clean_kreon_ss[85] = 0x00
                clean_kreon_ss[90] = 0xB5
                clean_kreon_ss[91] = 0x00
                clean_kreon_ss[93] = 0xB5
                clean_kreon_ss[94] = 0x00
                clean_kreon_ss[99] = 0x0F
                clean_kreon_ss[100] = 0x01
                clean_kreon_ss[102] = 0x0F
                clean_kreon_ss[103] = 0x01
        
        ss_crc = zlib.crc32(data)
        print(f"SS Hash: {ss_crc:08X}")
        if xgd == 2:
            clean_kreon_ss_crc = zlib.crc32(clean_kreon_ss)
            print(f"Redump SS Hash: {clean_kreon_ss_crc:08X}")
            clean_0800_ss_crc = zlib.crc32(clean_0800_ss)
            print(f"Fixed angles SS Hash: {clean_0800_ss_crc:08X}")
            abgx_ss_crc = zlib.crc32(abgx_ss)
            print(f"abgx360 filename: SS_{abgx_ss_crc:08X}.bin")
        if xgd == 3:
            clean_kreon_ss_crc = zlib.crc32(clean_kreon_ss)
            print(f"Redump SS Hash: {clean_kreon_ss_crc:08X}")
        if xgd == 4:
            clean_kreon_ss_crc = zlib.crc32(clean_kreon_ss)
            print(f"Redump SS Hash: {clean_kreon_ss_crc:08X}")
            abgx_ss_crc = zlib.crc32(abgx_ss)
            print(f"abgx360 filename: SS_{abgx_ss_crc:08X}.bin")
        
        parse_pfi(data, xgd)
        
        parse_ss(data, xgd, verbose)
        
        if xgd == 1:
            empty_ranges = [(0x011, 0x2D0), (0x2D4, 0x300), (0x3FF, 0x41F), (0x437, 0x43B), (0x44B, 0x49F), (0x4AB, 0x4BA), (0x7FF, 0x800)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if not all_zero:
                print("[WARNING] Unexpected data in reserved bytes")
        elif xgd == 2:
            empty_ranges = [(0x011, 0x100), (0x11C, 0x200), (0x2CF, 0x2D0), (0x2D4, 0x300), (0x302, 0x304), (0x400, 0x460), (0x470, 0x49E), (0x4A7, 0x4BA), (0x5EB, 0x5FA), (0x7FF, 0x800)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if not all_zero:
                print("[WARNING] Unexpected data in reserved bytes")
        elif xgd > 2:
            empty_ranges = [(0x011, 0x01B), (0x01C, 0x020), (0x0F5, 0x0FF), (0x302, 0x304), (0x400, 0x460), (0x470, 0x49E), (0x4A7, 0x4BA), (0x5EB, 0x5FA), (0x7FF, 0x800)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if not all_zero:
                print("[WARNING] Unexpected data in reserved bytes")
        
        else:
            print(f"[ERROR] Not a valid Xbox SS: Byte at 0x4BA is 0x{data[0]:02X}")
            return

if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        print(f"[ERROR] File file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
