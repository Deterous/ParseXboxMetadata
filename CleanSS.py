import os
import sys

def get_xgd_type(ss):
    layerbreak = (ss[13] << 16) | (ss[14] << 8) | ss[15]
    if layerbreak == 0x2033AF:
        return 1
    elif layerbreak == 0x20339F:
        return 2
    elif layerbreak == 0x238E0F:
        return 3
    else:
        return None

def clean_ss(ss, ssv2):
    xgd_type = get_xgd_type(ss)
    if xgd_type == 1:
        return True
    elif xgd_type == 2:
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
    elif xgd_type == 3:
        if any(x != 0 for x in ss[32:32+72]):
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
        else:
            ss[552] = 0x01
            ss[553] = 0x00
            ss[561] = 0x5B
            ss[562] = 0x00
            ss[570] = 0xB5
            ss[571] = 0x00
            ss[579] = 0x0F
            ss[580] = 0x01
        return True
    return False

def process_file(file_path, ssv2):
    try:
        if os.path.isfile(file_path) and os.path.getsize(file_path) == 2048:
            with open(file_path, 'rb+') as f:
                data = bytearray(f.read())
                if clean_ss(data, ssv2):
                    f.seek(0)
                    f.write(data)
                else:
                    print(f"Invalid SS: {file_path}")
        else:
            print(f"Invalid SS: {file_path}")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")

def process_directory(directory, recursive, ssv2):
    for root, _, files in os.walk(directory):
        for name in files:
            process_file(os.path.join(root, name), ssv2)
        if not recursive:
            break

def main():
    if len(sys.argv) < 2:
        print("Usage: python CleanSS.py <file|directory> [-r|--recursive] [-s|--ssv2]")
        return

    path = sys.argv[1]
    recursive = any(arg in ('-r', '--recursive') for arg in sys.argv[2:])
    ssv2 = any(arg in ('-s', '--ssv2') for arg in sys.argv[2:])

    if os.path.isdir(path):
        process_directory(path, recursive, ssv2)
    elif os.path.isfile(path):
        process_file(path, ssv2)
    else:
        print(f"Invalid path: {path}")

if __name__ == "__main__":
    main()
