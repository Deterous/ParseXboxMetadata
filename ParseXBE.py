import sys
import os
import datetime


def decode_title_id(byte_data):
    prefix = ''.join(map(lambda b: chr(b) if 0x41 <= b <= 0x5A or 0x30 <= b <= 0x39 else f'\\x{b:02X}', byte_data[3:1:-1]))
    serial = int.from_bytes(byte_data[:2], byteorder='little')
    return f"{prefix}-{serial:03d}"

def main(): 
    if len(sys.argv) < 2:
        print("Usage: python ParseXBE.py <filename.xbe>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        file_size = os.path.getsize(file_path)
        if file_size < 0x370:
            print(f"Error: File is too small to be a valid XBE file")
            sys.exit(1)
    except Exception as e:
        print(f"Error opening file: {e}")
        sys.exit(1)
    
    try:
        with open(file_path, 'rb') as f:
            # Read memory address
            f.seek(0x104)
            mem_offset = f.read(4)
            if len(mem_offset) != 4:
                raise ValueError("Unexpected read error at 0x104")
            mem_offset = int.from_bytes(mem_offset, byteorder='little')
            
            # Read header size
            f.seek(0x110)
            header_size = f.read(4)
            if len(header_size) != 4:
                raise ValueError("Unexpected read error at 0x110")
            header_size = int.from_bytes(header_size, byteorder='little')
            
            # Read xbe timestamp
            f.seek(0x114)
            xbe_timestamp = f.read(4)
            if len(xbe_timestamp) != 4:
                raise ValueError("Unexpected read error at xbe_timestamp")
            xbe_timestamp = int.from_bytes(xbe_timestamp, byteorder='little')
            xbe_timestamp = datetime.datetime.fromtimestamp(xbe_timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            
            # Read relative certificate address
            f.seek(0x118)
            cert_memory_offset = f.read(4)
            if len(cert_memory_offset) != 4:
                raise ValueError("Unexpected read error at 0x118")
            cert_memory_offset = int.from_bytes(cert_memory_offset, byteorder='little')
            
            # Determine absolute certificate address
            cert_offset = cert_memory_offset - mem_offset
            
            # Compare cert offset against header size
            if cert_offset != header_size:
                print(f"Warning: Parsed data may be incorrect due to unexpected XBE header in {file_path}.")
            
            # Read certificate size
            if cert_offset + 4 < file_size:
                f.seek(cert_offset)
                cert_size = f.read(4)
                if len(cert_size) != 4:
                    print(f"Unexpected read error at {hex(cert_offset)}")
                else:
                    cert_size = int.from_bytes(cert_size, byteorder='little')
                    if cert_size != 492:
                        print(f"Warning: Unusual certificate size {cert_size} in {file_path}")
            else:
                raise ValueError(f"Certificate address {hex(cert_offset)} is larger than XBE file size")
            
            # Check file size before continuing
            if cert_offset + 0xB0 > file_size:
                raise ValueError(f"Certificate file offset {hex(cert_offset + 204)} is larger than XBE file size {file_size}")
                
            # Print XBE timestamp
            print(f"XBE Timestamp: {xbe_timestamp}")
            
            # Read Cert Timestamp
            f.seek(cert_offset + 0x04)
            timestamp = f.read(4)
            if len(timestamp) != 4:
                raise ValueError("Unexpected read error at timestamp")
            timestamp = int.from_bytes(timestamp, byteorder='little')
            readable_time = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            print(f"Certificate Timestamp: {readable_time}")
            
            # Read Cert Title ID
            f.seek(cert_offset + 0x08)
            title_id = f.read(4)
            if len(title_id) != 4:
                raise ValueError("Unexpected read error at Title ID")
            title_id = decode_title_id(title_id)
            print(f"Title ID: {title_id}")
            
            # Read Cert Title Name
            f.seek(cert_offset + 0x0C)
            title_name = f.read(50)
            if len(title_name) != 50:
                raise ValueError("Unexpected read error at Title Name")
            title_name = title_name.decode('utf-16le')
            print(f"Title Name: {title_name}")
            
            # Read Alt Title IDs
            f.seek(cert_offset + 0x5C)
            alt_title_ids = f.read(40)
            if len(alt_title_ids) != 40:
                raise ValueError("Unexpected read error at Alt Title IDs")
            alt_title_id = []
            for i in range(0, len(alt_title_ids), 4):
                cur_title_id = alt_title_ids[i:i+4]
                if all(b == 0x00 for b in cur_title_id):
                    break
                alt_title_id.append(decode_title_id(cur_title_id))
            if len(alt_title_id) > 0:
                print("Alternate Title IDs:")
                for id in alt_title_id:
                    print(f"    {id}")
            
            # Read Allowed Media
            f.seek(cert_offset + 0x9C)
            allowed_media = f.read(4)
            if len(allowed_media) != 4:
                raise ValueError("Unexpected read error at Allowed Media")
            allowed_media_int = int.from_bytes(allowed_media, byteorder='little')
            print(f"Allowed Media: 0x{allowed_media_int:x}")
            
            # Read Game Region
            f.seek(cert_offset + 0xA0)
            game_region = f.read(4)
            if len(game_region) != 4:
                raise ValueError("Unexpected read error at Game Region")
            game_region_int = int.from_bytes(game_region, byteorder='little')
            print(f"Game Region: 0x{game_region_int:x}")
            
            # Read Game Ratings
            f.seek(cert_offset + 0xA4)
            game_ratings = f.read(4)
            if len(game_ratings) != 4:
                raise ValueError("Unexpected read error at Game Ratings")
            game_ratings_int = int.from_bytes(game_ratings, byteorder='little')
            print(f"Game Ratings: 0x{game_ratings_int:x}")
            
            # Read Disc Number
            f.seek(cert_offset + 0xA8)
            disc_num = f.read(4)
            if len(disc_num) != 4:
                raise ValueError("Unexpected read error at Disc Number")
            disc_num = int.from_bytes(disc_num, byteorder='little')
            print(f"Disc Number: {disc_num}")
            
            # Read Certificate Version
            f.seek(cert_offset + 0xAC)
            cert_version = f.read(4)
            if len(cert_version) != 4:
                raise ValueError("Unexpected read error at Certificate Version")
            cert_version = int.from_bytes(cert_version, byteorder='little')
            print(f"Certificate Version: {cert_version}")
            
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
