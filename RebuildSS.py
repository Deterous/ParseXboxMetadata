import sys
import os
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("The 'cryptography' module is needed to decrypt the Challenge Response Table.")
    print("Please install 'cryptography' using pip:")
    print("python -m pip install cryptography")
    raise


def clean_ss(ss, xgd):
    print(f"[INFO] Setting fixed angles")
    if xgd == 1:
        return True
    elif xgd == 2:
        ss[552] = 0x01
        ss[553] = 0x00
        ss[555] = 0x01 if ssv2 else 0x00
        ss[556] = 0x00
        ss[561] = 0x5B
        ss[562] = 0x00
        ss[564] = 0x5B if ssv2 else 0x00
        ss[565] = 0x00
        ss[570] = 0xB5
        ss[571] = 0x00
        ss[573] = 0xB5 if ssv2 else 0x00
        ss[574] = 0x00
        ss[579] = 0x0F
        ss[580] = 0x01
        ss[582] = 0x0F if ssv2 else 0x00
        ss[583] = 0x01 if ssv2 else 0x00
        return True
    elif xgd == 3:
        ss[72] = 0x01
        ss[73] = 0x00
        ss[75] = 0x01
        ss[76] = 0x00
        ss[81] = 0x5B
        ss[82] = 0x00
        ss[84] = 0x5B
        ss[85] = 0x00
        ss[90] = 0xB5
        ss[91] = 0x00
        ss[93] = 0xB5
        ss[94] = 0x00
        ss[99] = 0x0F
        ss[100] = 0x01
        ss[102] = 0x0F
        ss[103] = 0x01
        return True
    return False

def repair_ccrt2(data, xgd, cpr_mai):
    good_ss = bytearray(data)
    
    if xgd == 1:
        return None
    elif xgd == 3:
        offset = 0x20
    else:
        offset = 0x200
    
    if data[555] == 0x00 and data[556] == 0x00 and data[564] == 0x00 and data[565] == 0x00 and data[573] == 0x00 and data[574] == 0x00 and data[582] == 0x00 and data[583] == 0x00:
        is_kreon_ss = True
    else:
        is_kreon_ss = False
    
    key = bytes([0xD1, 0xE3, 0xB3, 0x3A, 0x6C, 0x1E, 0xF7, 0x70, 0x5F, 0x6D, 0xE9, 0x3B, 0xB6, 0xC0, 0xDC, 0x71])
    iv = bytearray(16)
    dcrt = bytearray(252)
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    for i in range(16):
        ct = bytes(data[0x304+i*16:0x304+(i+1)*16])
        if i == 15:
            dcrt[i*16:252] = ct[:12]
        else:
            pt = bytearray(cipher.update(ct))
            for j in range(16):
                pt[j] ^= iv[j]
            iv[:] = ct
            dcrt[i*16:(i+1)*16] = pt
    
    enc_response_count = 0
    for i in range(0x304, 0x400, 12):
        hex_str = ''.join(f'{b:02X}' for b in data[i:i+12])
        if hex_str != "000000000000000000000000":
            enc_response_count = enc_response_count + 1
    
    if enc_response_count != 21:
        print("[ERROR] Cannot safely repair with unexpected encrypted challenge count: {enc_response_count}")
        return None
    
    dcrtentry = []
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
                print("[ERROR] Cannot safely repair CT01 conflict")
                return None
    if CT01_firstCD != cpr_mai:
        print(f"[WARNING] CCRT ({int.from_bytes(CT01_firstCD, 'big'):04X}) does not match expected CPR_MAI ({int.from_bytes(cpr_mai, 'big'):04X})")
        print("[ERROR] Currently do not support safely fixing CPR_MAI mismatch")
        return None
    
    response_count = 0
    for i in range(23):
        hex_str = ''.join(f'{b:02X}' for b in data[0x730+i*9:0x730+i*9+9])
        if hex_str != "000000000000000000":
            response_count = response_count + 1
    
    rtentry = []
    for i in range(response_count):
        if (data[0x730+i*9] & 0xF0) == 0xF0:
            continue
        entry = {
            "RT": data[0x730+i*9],  # Response Type
            "CID": data[0x730+i*9+1],  # Challenge ID
            "Mod": data[0x730+i*9+2],
            "Data": data[0x730+i*9+3:0x730+i*9+9],  # incl SS ranges
            "CD": data[offset+i*9:offset+i*9+4],
            "Response": data[offset+i*9+4:offset+i*9+9],
            "angle": (data[offset+i*9+5] << 8) | data[offset+i*9+4],
            "angle2": (data[offset+i*9+8] << 8) | data[offset+i*9+7],
        }
        rtentry.append(entry)
    
    for crt in dcrtentry:
        if crt['CT'] != 0x01 and crt['CT'] != 0xE0 and crt['CT'] != 0x14 and crt['CT'] != 0x15 and crt['CT'] != 0x24 and crt['CT'] != 0x25 and (crt['CT'] & 0xF0) != 0xF0:
            print(f"[ERROR] Do not currently support repairing unexpected CT {crt['CT']:02X}")
            return None
    for entry in rtentry:
        for crt in dcrtentry:
            if crt['CID'] == entry['CID']:
                if (crt['CT'] == 0x15 and entry['RT'] != 0x01) or (crt['CT'] == 0x14 and entry['RT'] != 0x03) or (crt['CT'] == 0x25 and entry['RT'] != 0x05) or (crt['CT'] == 0x24 and entry['RT'] != 0x07):
                    print("[ERROR] Do not currently support repairing mismatched CT/RT")
                    return None
                if crt['CT'] != 0xE0 and crt['CT'] != 0x01:
                    if crt['CT'] == 0x24 or crt['CT'] == 0x25:
                        # Deal with angle measurements differently
                        zeroed_angles = False
                        if crt['angle'] > 359:
                            print(f"[ERROR] Cannot safely repair with invalid angle (>359deg) in challenge")
                            return None
                        if entry['angle'] > 359 or entry['angle2'] > 359:
                            print(f"[ERROR] Cannot safely repair with invalid angle (>359deg) in response")
                            return None
                        if crt['CD'] != entry['CD']:
                            print(f"[INFO] Fixing mismatched CD for CID {entry['CID']:02X}")
                            entry['CD'] = crt['CD']
                            if entry['CD'] == b'\x00\x00\x00\x00':
                                zeroed_angles = True
                        if zeroed_angles:
                            print("[WARNING] SS contains zeroed angle, RawSS is useless. Clean this SS!")
                        #angle_diff = abs((entry['angle'] - crt['angle'] + 180) % 360 - 180)
                        #if not zeroed_angles and angle_diff > 9:
                            #print(f"[WARNING] Angle {entry['angle']} varies significantly from expected {crt['angle']}")
                        #angle2_diff = abs((entry['angle2'] - crt['angle'] + 180) % 360 - 180)
                        #if not zeroed_angles and (xgd != 2 or not is_kreon_ss) and angle2_diff > 9:
                            #print(f"[WARNING] Angle2 {entry['angle2']} varies significantly from expected {crt['angle']}")
                        #if entry['angle'] == 359:
                            #print(f"[INFO] First angle is 359deg, incompatible with iXtreme 1.4")
                        #if entry['angle'] != entry['angle2'] and entry['angle'] == 0 and entry['angle2'] == 359:
                            #print(f"[INFO] SS has been fixed by abgx for iXtreme 1.4 compatibility reasons")
                        #elif entry['angle'] != entry['angle2'] and not is_kreon_ss:
                            #print(f"[WARNING] Mismatched angles in response: {entry['angle']} vs {entry['angle2']}")
                        break
                    elif crt['CD'] != entry['CD'] and crt['Response'] != entry['Response'][:-1]:
                        print(f"[INFO] Fixing mismatched CD and Response for CID {entry['CID']:02X}")
                        entry['CD'] = crt['CD']
                        entry['Response'] = crt['Response'][:4] + entry['Response'][4:]
                    elif crt['CD'] != entry['CD']:
                        print(f"[INFO] Fixing mismatched CD for CID {entry['CID']:02X}")
                        entry['CD'] = crt['CD']
                    elif crt['Response'] != entry['Response'][:-1]:
                        print(f"[INFO] Fixing mismatched Response for CID {entry['CID']:02X}")
                        entry['Response'] = crt['Response']
                    break
    
    for i, entry in enumerate(rtentry):
        if (good_ss[0x730+i*9] & 0xF0) == 0xF0:
            continue

        good_ss[0x730+i*9] = entry["RT"]
        good_ss[0x730+i*9+1] = entry["CID"]
        good_ss[0x730+i*9+2] = entry["Mod"]
        good_ss[0x730+i*9+3:0x730+i*9+9] = entry["Data"]
        good_ss[offset+i*9:offset+i*9+4] = entry["CD"]
        good_ss[offset+i*9+4:offset+i*9+9] = entry["Response"]
    
    clean_ss(good_ss, xgd)
    
    return good_ss


def rebuild_ss(data, xgd):
    # move cpr_mai and trim sector
    cpr_mai = data[0x007:0x00B]
    print(f"[INFO] CPR_MAI key of {cpr_mai.hex().upper()}")
    data = bytearray(data[0x00C:0x80C])
    if xgd == 3:
        data[0x0F0:0x0F4] = cpr_mai
    else:
        data[0x2D0:0x2D4] = cpr_mai

    # decode SS ranges and copy - thanks to RibShark
    scramble_indices = data[0x730:0x800]
    scramble_indices = bytearray(a ^ b for a, b in zip(scramble_indices, cpr_mai * (len(scramble_indices) // 4)))

    ss_range = bytearray(0xCF)
    ss_range_scrambled = data[0x661:0x730]
    for i in range(0, len(scramble_indices) - 1):
        ss_range[i] = ss_range_scrambled[scramble_indices[i]]

    data[0x661:0x730] = ss_range
    data[0x730:0x7FF] = ss_range

    if xgd < 2:
        return data

    if data[0x300] != 2:
        print(f"[ERROR] Cannot safely repair with unexpected CCRT Version: 0x{data[0x300]:02X}")
        return None
    if data[0x301] != 21:
        print(f"[ERROR] Cannot safely repair with unexpected CCRT Count: 0x{data[0x301]:02X}")
        return None
    if data[0x65F] != 0x02:
        print(f"[ERROR] Cannot safely repair with unexpected value at 0x66B: {data[0x65F]:02X}")
        return None
    if data[0x49E] != 0x04:
        print(f"[ERROR] Cannot safely repair with unexpected value at 0x4AA: 0x{data[0x49E]:02X}")
        return None
    if data[0x661:0x730] != data[0x730:0x7FF]:
        print("[ERROR] Cannot safely repair when duplicated SS range does not match")
        return None
    return repair_ccrt2(data, xgd, cpr_mai)


def rebuild_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read(2064)
    
    if len(data) < 2064:
        print("[ERROR] Not a valid raw SS: <2064 bytes")
        return
    
    xgd = 0
    layer0_end = data[0x19:0x1C]
    if layer0_end == bytes([0x20, 0x33, 0xAF]):
        xgd = 1
    elif layer0_end == bytes([0x20, 0x33, 0x9F]):
        xgd = 2
    elif layer0_end == bytes([0x23, 0x8E, 0x0F]):
        xgd = 3
    else:
        print(f"[ERROR] Not a valid SS: Bad layerbreak")
        return
    
    if xgd == 2:
        empty_ranges = [(0x01D, 0x10C), (0x128, 0x20C), (0x2DB, 0x2DC), (0x2E0, 0x30C), (0x30E, 0x310), (0x40C, 0x46C), (0x47C, 0x4AA), (0x4B3, 0x4C6), (0x5F7, 0x606)]
        all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
        if not all_zero:
            print("[ERROR] Cannot safely rebuild unexpected XGD2")
            return
    elif xgd == 3:
        empty_ranges = [(0x01D, 0x027), (0x028, 0x02C), (0x101, 0x10B), (0x30E, 0x310), (0x40C, 0x46C), (0x47C, 0x4AA), (0x4B3, 0x4C6), (0x5F7, 0x606)]
        all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
        if not all_zero:
            print("[ERROR] Cannot safely rebuild unexpected XGD3")
            return
    
    good_ss = rebuild_ss(data, xgd)
    if good_ss is not None:
        with open(file_path, 'wb') as f:
            f.write(good_ss)
            return


if __name__ == "__main__":
    try:
        if len(sys.argv) < 2 or len(sys.argv) > 4:
            print("Usage: python RebuildSS.py <filename|directory> [-r|--recursive] [-s|--ss-only]")
            print()
            print("Options:")
            print("input: SS file path to rebuild, or directory of SS files to rebuild")
            print("-r, --recursive\t Rebuilds all files in dir recursively")
            print("-s, --ss-only\t Only rebuilds .bin files in dir that start with SS")
            sys.exit(0)
        
        input_path = None
        recursive = False
        ss_only = False
        for arg in sys.argv[1:]:
            if arg in ("-r", "--recursive"):
                recursive = True
            elif arg in ("-s", "--ss-only"):
                ss_only = True
            else:
                input_path = arg
        
        if not input_path:
            print("[ERROR] No valid filename provided")
            sys.exit(0)
        
        if os.path.isdir(input_path):
            if recursive:
                for root, _, files in os.walk(input_path):
                    for file in files:
                        if not ss_only or (file.startswith("SS") and file.endswith(".bin")):
                            file_path = os.path.join(root, file)
                            print(file_path)
                            rebuild_file(file_path)
            else:
                for entry in os.listdir(input_path):
                    file_path = os.path.join(input_path, entry)
                    if os.path.isfile(file_path) and (not ss_only or (os.path.basename(file_path).startswith("SS") and file_path.endswith(".bin"))):
                        print(file_path)
                        rebuild_file(file_path)
        elif os.path.isfile(input_path):
            rebuild_file(input_path)
        else:
            print(f"[ERROR] Invalid path: {input_path}")
    except Exception as e:
        print(f"[ERROR] {e}")
