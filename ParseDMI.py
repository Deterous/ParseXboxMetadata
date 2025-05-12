import sys
import datetime


def print_filetime(data):
    filetime = int.from_bytes(data[0x010:0x018], "little")
    time = divmod(filetime - 0x19DB1DED53E8000, 10000000)
    time = datetime.datetime.fromtimestamp(time[0], datetime.UTC).replace(microsecond=time[1] // 10)
    print(f"DMI Timestamp: {time.strftime(f"%Y-%m-%d %H:%M:%S%f")}")


def print_trailer(data):
    pfi = data[0x7E0:0x7E4]
    
    pfi_map = {
        bytes.fromhex('9A986A27'): '8FC52135',  # XGD1
        bytes.fromhex('9B321F36'): 'E9B8ECFE',  # Wave 0 (Experience Disc 1.0)
        bytes.fromhex('48083A81'): '739CEAB3',  # Wave 1
        bytes.fromhex('B884AC0E'): 'A4CFB59C',  # Wave 2
        bytes.fromhex('7F24F5B8'): '2A4CCBD3',  # Wave 3
        bytes.fromhex('2F5E9C87'): '05C6C409',  # Wave 4-7
        bytes.fromhex('A9308344'): '0441D6A5',  # Wave 8-9
        bytes.fromhex('66481ECA'): 'E18BC70B',  # Wave 10-12
        bytes.fromhex('6F8144F6'): '40DCB18F',  # Wave 13
        bytes.fromhex('D791F116'): '23A198FC',  # Wave 14-15
        bytes.fromhex('E60935F5'): 'AB25DB47',  # Wave 16
        bytes.fromhex('C10CD2DC'): '169EF597',  # Wave 17-18
        bytes.fromhex('0C916366'): '032CCF37',  # Wave 19
        bytes.fromhex('12F3C56D'): 'F48D24B8',  # Wave 20
        bytes.fromhex('BDD34C19'): 'E1647069',  # XGD3 #1 (Halo Reach Preview, Kinect Rush)
        bytes.fromhex('0FC5ED02'): '26AF4C58',  # XGD3 #2
        bytes.fromhex('B0D59CD1'): '26675ADB',  # XGD2 Hybrid (Xbox 360 Trial Disc)
    }
    if pfi in pfi_map:
        print(f"PFI CRC: {pfi_map[pfi]}")
    else:
        print("PFI CRC: Unknown")
    
    xbox = data[0x7E4:0x7F0]
    if xbox == bytes.fromhex('0002000058424F5800000000'):
        print("Xbox Signature: Valid")
    else:
        print("Xbox Signature: Invalid")


def main():
    if len(sys.argv) != 2:
        print("Usage: python ParseDMI.py <filename>")
    
    filename = sys.argv[1]
    
    with open(filename, 'rb') as f:
        data = f.read(2048)
        if len(data) < 2048:
            print("Error: Not a valid DMI: <2048 bytes")
            return
        
        if data[0] == 0x01:
            print("System: Xbox (XGD1)")
            
            xmid = data[0x08:0x10].split(b'\x00')[0].decode(errors='ignore')
            print(f"XMID: {xmid}")
            
            print_filetime(data)
            
            if data[0x634:0x800] == b'\x00' * 460:
                print("DMI Trailer: blank")
            else:
                print_trailer(data)
            
            empty_ranges = [(0x001, 0x008), (0x019, 0x634)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if all_zero:
                print("Check: No unusual values detected!")
            else:
                print("Check: Unusual values detected!")
        
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
            print("Media ID: ", ''.join(f"{b:02X}" for b in media_id))
            
            xemid = data[0x40:0x50].split(b'\x00')[0].decode(errors='ignore')
            print(f"XeMID: {xemid}")
            
            print_trailer(data)
            
            empty_ranges = [(0x001, 0x010), (0x19, 0x20), (0x30, 0x40), (0x50, 0x634)]
            all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
            if all_zero:
                print("Check: No unusual values detected!")
            else:
                print("Check: Unusual values detected!")
        
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
