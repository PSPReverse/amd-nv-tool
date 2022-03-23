import sys

from .nv_data import NVData


def main():
    if len(sys.argv) < 3:
        print(f"Error: more arguments are required")
        print(f"usage: amdnvtool romfile lsb_key_hex")
        sys.exit(1)

    romfile = sys.argv[1]
    lsb_key_hex = sys.argv[2]

    nv_data = NVData.from_file_and_hex(romfile, lsb_key_hex)

    #nv_data.print_parsed()
    nv_data.print_by_context()


if __name__ == '__main__':
    main()
