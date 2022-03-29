import sys

from .nv_data import NVData


def main():
    if len(sys.argv) < 3:
        print(f"Error: more arguments are required")
        print(f"usage: amdnvtool romfile [-s <secret_hex> | lsb_key_hex]")
        sys.exit(1)

    romfile = sys.argv[1]
    lsb_key_hex = sys.argv[2]
    if lsb_key_hex == '-s':
        secret_hex = sys.argv[3]
        nv_data = NVData.from_file_and_secret_hex(romfile, secret_hex)
    else:
        nv_data = NVData.from_file_and_lsb_key_hex(romfile, lsb_key_hex)

    nv_data.raw.assert_all_hmacs_are_valid(nv_data.keys.hmac_key)

    #nv_data.print_parsed()
    #nv_data.print_by_context()
    nv_data.print_json_by_context()


if __name__ == '__main__':
    main()
