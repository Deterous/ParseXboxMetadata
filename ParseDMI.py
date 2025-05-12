import sys
import datetime


def print_filetime(data):
    filetime = int.from_bytes(data[0x010:0x018], "little")
    time = divmod(filetime - 0x19DB1DED53E8000, 10000000)
    time = datetime.datetime.fromtimestamp(time[0], datetime.UTC).replace(microsecond=time[1] // 10)
    if time.strftime(f"%H:%M:%S%f") == "00:00:00000000":
        print(f"DMI Date: {time.strftime(f"%Y-%m-%d")}")
    else:
        print(f"DMI Datetime: {time.strftime(f"%Y-%m-%d %H:%M:%S%f")}")


def print_trailer(data, verbose):
    pfi = data[0x7DC:0x7E4]
    
    pfi_map = {
        bytes.fromhex('F56BBBAF9A986A27'): '8FC52135',  # XGD1
        bytes.fromhex('E771E4509B321F36'): 'E9B8ECFE',  # Wave 0 (Experience Disc 1.0)
        bytes.fromhex('724EA8F848083A81'): '739CEAB3',  # Wave 1
        bytes.fromhex('7F287181B884AC0E'): 'A4CFB59C',  # Wave 2
        bytes.fromhex('B92884797F24F5B8'): '2A4CCBD3',  # Wave 3
        bytes.fromhex('313DE4782F5E9C87'): '05C6C409',  # Wave 4-7
        bytes.fromhex('5075273CA9308344'): '0441D6A5',  # Wave 8-9
        bytes.fromhex('6E719E5B66481ECA'): 'E18BC70B',  # Wave 10-12
        bytes.fromhex('008EDE9B6F8144F6'): '40DCB18F',  # Wave 13
        bytes.fromhex('180DD029D791F116'): '23A198FC',  # Wave 14-15
        bytes.fromhex('18EB8B92E60935F5'): 'AB25DB47',  # Wave 16
        bytes.fromhex('6F926559C10CD2DC'): '169EF597',  # Wave 17-18
        bytes.fromhex('07E9C4770C916366'): '032CCF37',  # Wave 19
        bytes.fromhex('0C0BA0C912F3C56D'): 'F48D24B8',  # Wave 20
        bytes.fromhex('FA4BE3C4BDD34C19'): 'E1647069',  # XGD3 #1 (Halo Reach Preview, Kinect Rush)
        bytes.fromhex('26FB858A0FC5ED02'): '26AF4C58',  # XGD3 #2
        bytes.fromhex('CFE8ADB9B0D59CD1'): '26675ADB',  # XGD2 Hybrid (Xbox 360 Trial Disc)
    }
    if pfi in pfi_map:
        print(f"PFI CRC: {pfi_map[pfi]}")
    else:
        print("PFI CRC: Unknown")
    
    xbox = data[0x7E4:0x7F0]
    if xbox == bytes.fromhex('0002000058424F5800000000'):
        if verbose:
            print("Xbox Signature: Valid")
    else:
        print("Xbox Signature: Invalid")
    
    if verbose:
        print(f"Final Checksum: {int.from_bytes(data[0x7F0:0x800], 'big'):016X}")


def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("Usage: python ParseDMI.py <filename> [-v, --verbose]")
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
            print("Error: Not a valid XGD2 DMI")
            return
        
        if data[0] == 0x01:
            print("System: Xbox (XGD1)")
            
            xmid = data[0x08:0x10].split(b'\x00')[0].decode(errors='ignore')
            print(f"XMID: {xmid}")
            
            print_filetime(data)
            
            if data[0x634:0x800] != b'\x00' * 460:
                print_trailer(data, verbose)
            
            empty_ranges = [(0x001, 0x008), (0x019, 0x634)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if all_zero and verbose:
                print("All reserved bytes zeroed")
            elif not all_zero:
                print("Warning: Unexpected data in reserved bytes")
        
        elif data[0] == 0x02:
            print("System: Xbox 360 (XGD2/3)")
            
            print_filetime(data)
            
            key_id = data[0x018]
            if key_id == 1:
                print("XOR Key: Beta")
            elif key_id == 2:
                print("XOR Key: Retail")
            else:
                print(f"XOR Key: {key_id}")
            
            media_id = data[0x20:0x30]
            media_id_str = ''.join(f"{b:02X}" for b in media_id)
            print(f"Media ID: {media_id_str[:-8] + '-' + media_id_str[-8:]}")
            
            xemid = data[0x40:0x50].split(b'\x00')[0].decode(errors='ignore')
            print(f"XeMID: {xemid}")
            
            print_trailer(data, verbose)
            
            empty_ranges = [(0x001, 0x010), (0x19, 0x20), (0x30, 0x40), (0x50, 0x634)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if all_zero and verbose:
                print("All reserved bytes zeroed")
            elif not all_zero:
                print("Warning: Unexpected data in reserved bytes")
        
        else:
            print(f"Error: Not a valid Xbox DMI: First byte is 0x{data[0]:02X}")
            return

if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
