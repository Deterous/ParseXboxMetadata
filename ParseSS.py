import sys
import datetime
import zlib


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
    
    if xgd > 1:
        print(f"SHA-1 (Unknown): {int.from_bytes(data[0x108:0x11B], 'big'):040X}")
        
        response_count = 0
        for i, offset in enumerate(range(0x200, 0x2CF, 9), start=1):
            hex_str = ''.join(f'{b:02X}' for b in data[offset:offset + 9])
            if hex_str != "000000000000000000":
                response_count = response_count + 1
                if verbose:
                    print(f"Challenge Response #{i:02}: 0x{hex_str}")
        print(f"Challenge Responses: {response_count}")
    
    if xgd == 4:
        cpr_mai = int.from_bytes(data[0x0F0:0x0F4], byteorder='big')
        print(f"CPR_MAI Key: {cpr_mai:08X}")
    else:
        cpr_mai = int.from_bytes(data[0x2D0:0x2D4], byteorder='big')
        print(f"CPR_MAI Key: {cpr_mai:08X}")
    
    if (xgd == 1 and data[0x300] != 1) or (xgd > 1 and data[0x300] != 2):
        print(f"Unexpected CCRT Version: 0x{data[0x300]:02X}")
    if (xgd == 1 and data[0x301] != 23) or (xgd > 1 and data[0x301] != 21):
        print(f"Unexpected CCRT Count: 0x{data[0x301]:02X}")
    
    if xgd == 1:
        enc_response_count = 0
        for i, offset in enumerate(range(0x302, 0x3FF, 11), start=1):
            hex_str = ''.join(f'{b:02X}' for b in data[offset:offset + 11])
            if hex_str != "0000000000000000000000":
                enc_response_count = enc_response_count + 1
                if verbose:
                    print(f"enCrypted Challenge Response #{i:02}: 0x{hex_str}")
        print(f"enCrypted Challenge Responses: {enc_response_count}")
        
        creation_time = filetime(data[0x41F:0x427])
        if creation_time == "":
            print(f"[WARNING] Invalid Creation FILETIME: {int.from_bytes(data[0x41F:0x427], 'big'):016X}")
        else:
            print(f"Creation Timestamp: {creation_time}")
        
        if data[0x427:0x437] != b'\x00' * 16:
            if verbose:
                print(f"Certificate Hash: {int.from_bytes(data[0x427:0x437], 'big'):016X}")
        
        if verbose:
            print(f"Certificate Ver Hash: {int.from_bytes(data[0x43B:0x44B], 'big'):016X}")
    elif xgd > 1:
        enc_response_count = 0
        for i, offset in enumerate(range(0x304, 0x400, 9), start=1):
            hex_str = ''.join(f'{b:02X}' for b in data[offset:offset + 9])
            if hex_str != "000000000000000000":
                enc_response_count = enc_response_count + 1
                if verbose:
                    print(f"enCrypted Challenge Response #{i:02}: 0x{hex_str}")
        print(f"enCrypted Challenge Responses: {enc_response_count}")
        
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
        print(f"Unknown Hash: {int.from_bytes(data[0x4BB:0x4CB], 'big'):016X}")
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
        print(f"Mastering SHA-1: {int.from_bytes(data[0x5FB:0x60B], 'big'):016X}")
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
            print("XGD3 with SSv1")
        
        clean_ss = bytearray(data)
        abgx_ss = bytearray(data)
        if xgd == 2 or xgd == 3:
            for i in range(0x200, 0x300):
                abgx_ss[i] = 0xFF
        elif xgd == 4:
            for i in range(0x20, 0xF4):
                abgx_ss[i] = 0xFF
        
        if xgd == 2:
            if data[552] == 0x01 and data[553] == 0x00 and data[555] == 0x00 and data[556] == 0x00 and data[561] == 0x5B and data[562] == 0x00 and data[564] == 0x00 and data[565] == 0x00 and data[570] == 0xB5 and data[571] == 0x00 and data[573] == 0x00 and data[574] == 0x00 and data[579] == 0x0F and data[580] == 0x01 and data[582] == 0x00 and data[583] == 0x00:
                print("XGD2: Clean")
            else:
                print("XGD2: Not Clean")
                clean_ss[552] = 0x01
                clean_ss[553] = 0x00
                clean_ss[555] = 0x00
                clean_ss[556] = 0x00
                clean_ss[561] = 0x5B
                clean_ss[562] = 0x00
                clean_ss[564] = 0x00
                clean_ss[565] = 0x00
                clean_ss[570] = 0xB5
                clean_ss[571] = 0x00
                clean_ss[573] = 0x00
                clean_ss[574] = 0x00
                clean_ss[579] = 0x0F
                clean_ss[580] = 0x01
                clean_ss[582] = 0x00
                clean_ss[583] = 0x00
        elif xgd == 3:
            if data[552] == 0x01 and data[553] == 0x00 and data[561] == 0x5B and data[562] == 0x00 and data[570] == 0xB5 and data[571] == 0x00 and data[579] == 0x0F and data[580] == 0x00:
                print("XGD3 SSv1: Clean")
            else:
                print("XGD3 SSv1: Not Clean")
                clean_ss[552] = 0x01
                clean_ss[553] = 0x00
                clean_ss[561] = 0x5B
                clean_ss[562] = 0x00
                clean_ss[570] = 0xB5
                clean_ss[571] = 0x00
                clean_ss[579] = 0x0F
                clean_ss[580] = 0x00
        elif xgd == 4:
            if data[72] == 0x01 and data[73] == 0x00 and data[75] == 0x01 and data[76] == 0x00 and data[81] == 0x5B and data[82] == 0x00 and data[84] == 0x5B and data[85] == 0x00 and data[90] == 0xB5 and data[91] == 0x00 and data[93] == 0xB5 and data[94] == 0x00 and data[99] == 0x0F and data[100] == 0x01 and data[102] == 0x0F and data[103] == 0x01:
                print("XGD3 SSv2: Clean")
            else:
                print("XGD3 SSv2: Not Clean")
                clean_ss[72] = 0x01
                clean_ss[73] = 0x00
                clean_ss[75] = 0x01
                clean_ss[76] = 0x00
                clean_ss[81] = 0x5B
                clean_ss[82] = 0x00
                clean_ss[84] = 0x5B
                clean_ss[85] = 0x00
                clean_ss[90] = 0xB5
                clean_ss[91] = 0x00
                clean_ss[93] = 0xB5
                clean_ss[94] = 0x00
                clean_ss[99] = 0x0F
                clean_ss[100] = 0x01
                clean_ss[102] = 0x0F
                clean_ss[103] = 0x01
        
        ss_crc = zlib.crc32(data)
        print(f"SS Hash: {ss_crc:8X}")
        if xgd > 1:
            clean_ss_crc = zlib.crc32(clean_ss)
            print(f"Cleaned SS Hash: {clean_ss_crc:8X}")
            abgx_ss_crc = zlib.crc32(abgx_ss)
            print(f"abgx360 SS Hash: {abgx_ss_crc:8X}")
        
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
