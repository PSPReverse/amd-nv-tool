import sys

from .nv_data import NVData


def main():
    nv_data = NVData.from_file(sys.argv[1], None)

    #nv_data.print_parsed()
    nv_data.print_by_context()


if __name__ == '__main__':
    main()
