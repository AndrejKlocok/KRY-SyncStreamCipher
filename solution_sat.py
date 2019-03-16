import argparse
from z3 import *

plaintextName       = "bis.txt"
ciphertextName      = "bis.txt.enc"

N_B = 32
N = 8 * N_B

def sat_solution(args):
    # get first N_B bytes of key stream
    with open(args.path + "/" + plaintextName, "rb") as file:
        plain_bytes = file.read(N_B)

    with open(args.path + "/" + ciphertextName, "rb") as file:
        cipher_bytes = file.read(N_B)

    key_stream = int.from_bytes(plain_bytes, 'little') ^ int.from_bytes(cipher_bytes, 'little')

    for i in range(N // 2):
        s = Solver()

    print(key_stream.to_bytes(N_B, 'little').decode())


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str,
                        help="path to dictionary with secret files")
    args = parser.parse_args()

    sat_solution(args)

    pass


if __name__ == '__main__':
    main()
