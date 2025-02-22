import sys
import datetime


def main():
    if len(sys.argv) != 2:
        print("Usage: python ParseXbox360DMI.py <filename>")
    
    filename = sys.argv[1]
    
    with open(filename, 'rb') as f:
        data = f.read(2048)
        if len(data) < 2048:
            print("Error: Not a valid XGD2 DMI")
            return
        
        if data[0] != 0x02:
            print("Error: Not a valid XGD2 DMI")
            return
        
        filetime = int.from_bytes(data[0x010:0x018], "little")
        time = divmod(filetime - 0x19DB1DED53E8000, 10000000)
        time = datetime.datetime.fromtimestamp(time[0], datetime.UTC).replace(microsecond=time[1] // 10)
        print(f"DMI Timestamp: {time.strftime(f"%Y-%m-%d %H:%M:%S%f")}")
        
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
        
        empty_ranges = [(0x001, 0x010), (0x19, 0x20), (0x30, 0x40), (0x50, 0x634)]
        all_zero = all(data[start:end] == b'\x00' * (end - start) for start, end in empty_ranges)
        if all_zero:
            print("Check: No unusual values detected!")
        else:
            print("Check: Unusual values detected!")

if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")