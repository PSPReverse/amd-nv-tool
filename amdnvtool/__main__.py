import sys

from . import NVData


def main():
    try:
        nv_data = NVData.from_file(sys.argv[1])
    except IndexError:
        nv_data = NVData.from_stdin()
    #nv_data.print_parsed()
    nv_data.print_by_context()


if __name__ == '__main__':
    main()
