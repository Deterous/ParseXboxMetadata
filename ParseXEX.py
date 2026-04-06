import sys
import os
import datetime


def decode_title_id(byte_data):
    prefix = ''.join(map(lambda b: chr(b) if 0x41 <= b <= 0x5A or 0x30 <= b <= 0x39 else f'\\x{b:02X}', byte_data[3:1:-1]))
    serial = int.from_bytes(byte_data[:2], byteorder='little')
    return f"{prefix}-{serial:03d}"

def main(): 
    if len(sys.argv) < 2:
        print("Usage: python ParseXEX.py <filename.xex>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        file_size = os.path.getsize(file_path)
        if file_size < 0x19c:
            print(f"Error: File is too small to be a valid XEX file")
            sys.exit(1)
    except Exception as e:
        print(f"Error opening file: {e}")
        sys.exit(1)
    
    try:
        with open(file_path, 'rb') as f:
            # Check XEX file header
            magic = f.read(4)
            if len(magic) != 4:
                raise ValueError("Unexpected read error at 0x0")
            if magic != b"XEX2":
                print(f"Error: Not a valid XEX file")
                sys.exit(1)
            
            # Read certificate address
            f.seek(0x10)
            cert_offset = f.read(4)
            if len(cert_offset) != 4:
                raise ValueError("Unexpected read error at 0x10")
            cert_offset = int.from_bytes(cert_offset, byteorder='big')
            
            # Read optional header count
            optional_header_count = f.read(4)
            if len(optional_header_count) != 4:
                raise ValueError("Unexpected read error at 0x14")
            optional_header_count = int.from_bytes(optional_header_count, byteorder='big')
            
            # Read optional headers
            optional_header_id = [0] * optional_header_count
            optional_header_data = [0] * optional_header_count
            for i in range(optional_header_count):
                header_id = f.read(4)
                if len(header_id) != 4:
                    raise ValueError(f"Unexpected read error for optional header ID {i}")
                optional_header_id[i] = int.from_bytes(header_id, byteorder='big')
                header_data = f.read(4)
                if len(header_data) != 4:
                    raise ValueError(f"Unexpected read error for optional header data {i}")
                optional_header_data[i] = int.from_bytes(header_data, byteorder='big')
            
            # Parse Certificate
            f.seek(cert_offset + 320)
            media_id = f.read(16)
            if len(media_id) != 16:
                raise ValueError("Unexpected read error at Media ID")
            print(f"Media ID: {media_id[:12].hex().upper()}-{media_id[12:].hex().upper()}")

            REGIONS = {
                "NTSC/U": 0x00_00_00_FF,
                "Japan": 0x00_00_01_00,
                "China": 0x00_00_02_00,
                "Other Asia": 0x00_00_F8_00,
                "NTSC/J (Unknown 0xF9)": 0x00_00_F9_00,
                "NTSC/J (Excludes China)": 0x00_00_FD_00,
                "Oceania": 0x00_01_00_00,
                "Europe": 0x00_FE_00_00,
                "PAL": 0x00_FF_00_00,
                "Region Free": 0xFF_FF_FF_FF,
            }
            
            f.seek(cert_offset + 376)
            region = f.read(4)
            if len(region) != 4:
                raise ValueError("Unexpected read error at Region")
            parsed_region = "Unknown Region"
            val = int.from_bytes(region, byteorder='big')
            if val == 0xFFFFFFFF:
               parsed_region = "Region Free"
            else:
                matches = []
                if (val & 0x000000FF) == 0x000000FF:
                    matches.append("NTSC/U")

                if (val & 0x00FF0000) == 0x00FF0000:
                    matches.append("PAL")
                else:
                    if (val & 0x00FE0000) == 0x00FE0000: matches.append("Europe")
                    if (val & 0x00010000) == 0x00010000: matches.append("Oceania")
                
                if (val & 0x0000FF00) == 0x0000FF00:
                    matches.append("NTSC/J")
                elif (val & 0x0000FD00) == 0x0000FD00:
                    matches.append("NTSC/J, Excluding China")
                elif (val & 0x0000F900) == 0x0000F900:
                    matches.append("NTSC/J, Unknown 0xF9")
                else:
                    if (val & 0x0000F800) == 0x0000F800: matches.append("Other Asia")
                    if (val & 0x00000200) == 0x00000200: matches.append("China")
                    if (val & 0x00000100) == 0x00000100: matches.append("Japan")
                
                parsed_region = ", ".join(matches)
            print(f"Region: {region.hex().upper()} ({parsed_region})")



    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
