from IPython import embed
import sys
from . import *

def read_file_bytes(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

def main():
    nv_bytes = read_file_bytes(sys.argv[1])
    nv_data = raw.NVData(nv_bytes)
    embed()

if __name__ == "__main__":
    main()

