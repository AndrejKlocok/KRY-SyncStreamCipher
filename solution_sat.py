import argparse
from z3 import *

plaintextName = "bis.txt"
ciphertextName = "bis.txt.enc"

N_B = 32
N = 8 * N_B

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str,
                        help="path to dictionary with secret files")
    args = parser.parse_args()

    with open(args.path + "/" + plaintextName, "rb") as file:
        plain_bytes = file.read(N_B)

    with open(args.path + "/" + ciphertextName, "rb") as file:
        cipher_bytes = file.read(N_B)

    # keystream
    key_stream = int.from_bytes(plain_bytes, 'little') ^ int.from_bytes(cipher_bytes, 'little')

    # Create bits array and append Msb and Lsb
    bits_array = [Bool("<bit %d>" % i) for i in range(N)]
    bits_array = [bits_array[-1]] + bits_array + [bits_array[0]]

    for i in range(N // 2):
        s = Solver()

        for x in range(N):
            # create expression of dependency for bit x according to table for Y = 1
            expression = Or(
                And(Not(bits_array[x+2]), Not(bits_array[x+1]), (bits_array[x])),
                And(Not(bits_array[x+2]), bits_array[x+1], Not(bits_array[x])),
                And(bits_array[x+2], Not(bits_array[x+1]), Not(bits_array[x])),
                And(bits_array[x+2], bits_array[x+1], Not(bits_array[x]))
            )
            # according to current byte
            if ((1 << x) & key_stream) > 0:
                s.add(expression)
            else:
                # for 0 we simply do Not(exp)
                s.add(Not(expression))

        # check sat
        if s.check() == sat:
            model = s.model()
            tmp = 0
            # convert bool array to keystream
            for n in range(N):
                tmp |= (1 if is_true(model[bits_array[n]]) else 0) << n
            # update keystream
            key_stream = tmp

        else:
            print("Could not reverse key stream")
            exit(1)

    # output is divided in half
    wtf = key_stream.to_bytes(N_B, 'little').decode()
    l = len(wtf)
    print(wtf[l//2:] + wtf[:l//2])
    pass



if __name__ == '__main__':
    main()
