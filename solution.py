import argparse
from itertools import product

plaintextName       = "bis.txt"
ciphertextName      = "bis.txt.enc"
hintName            = "hint.gif.enc"
supercipherName     = "super_cipher.py.enc"
supercipherNameDec  = "super_cipher.py"

'''
    From super_cipher.py we know how key stream is generated in step function
'''

N_B = 32
N = 8 * N_B
SUB = [0, 1, 1, 0, 1, 0, 1, 0]

def step(x, SUB):
    '''
    Modified step function from partly decipher script file
    :param x:
    :param SUB:
    :return:
    '''
    x = (x & 1) << N+1 | x << 1 | x >> N-1
    y = 0
    for i in range(N):
        y |= SUB[(x >> i) & 7] << i
    return y


def reverse_step(y):
    '''
    :param y:   keystream
    :return:    step^-1(y)
    '''
    # mapping tables
    mapping_sub = {0: [0, 3, 5, 7], 1: [1, 2, 4, 6]}
    mapping_val0 = {0: [0], 1: [5], 2: [], 3: [3, 7]}
    mapping_val1 = {0: [4], 1: [1], 2: [2, 6], 3: []}

    # init values according to last bit
    values = mapping_sub[y & 1]
    # for 1 - 255
    for i in range(1, N):
        new_values = []             # array of potential key streams
        sub_index = (y >> i) & 1    # check i-th bit -> 0/1
        for val in values:          # for each existing potential key stream
            last2b = (val >> i) & 3     # check last 2 bites
            # look up mapping for 2bites in i-th bit mapping dictionary
            if sub_index:
                mapping = mapping_val1[last2b]
            else:
                mapping = mapping_val0[last2b]
            # for each potential mapping create new key stream value
            for m in mapping:
                new_values.append(m << i | val)
        # throw away those key stream values, in which we did not find mapping
        values = new_values

    # chose correct value of potential key stream
    for val in values:
        if (val >> 256) == (val & 3):           # check match of first/last 2 bits
            return (val >> 1) & ((1 << N) - 1)  # return reversed value

    print("Could not reverse key stream")
    exit(1)


def getPartOfscript(args):
    '''
    Try to decipher super_cipher.py file to get more info
    :param args: arguments
    :return:
    '''

    # open files and read their content
    with open(args.path + "/" + plaintextName, "rb") as file:
        plaintext = file.read()

    with open(args.path + "/" + ciphertextName, "rb") as file:
        ciphertext = file.read()

    with open(args.path + "/" + supercipherName, "rb") as file:
        scriptText = file.read()

    # get keystream from bis.txt and bis.txt.enc
    keystream = [ a^b for a, b in zip(plaintext, ciphertext)]

    # with keystream dec super_cipher.py.enc
    script = [ a^b for a, b in zip(keystream, scriptText)]

    # get length difference
    print("Length keystream: " + str(len(keystream)))
    print("Length scriptText: " + str(len(scriptText)))

    # decode ascii chars
    out = ''.join(chr(c) for c in script)

    print(out)
    pass


def decrypt(script_file, dec_file, SUB, keystr_step):
    '''
    Writes decrypted N_B bytes to destination file
    :param script_file:     source file
    :param dec_file:        destination file
    :param SUB:             SUB vector
    :param keystr_step:     key stream step
    :return:
    '''
    # read from script file again
    script_bytes = script_file.read(N_B)

    # decrypt whole file
    while script_bytes:
        # generate new key step
        keystr_step = step(int.from_bytes(keystr_step, 'little'), SUB).to_bytes(N_B, 'little')

        # decrypt bytes
        dec_byte_step = [a ^ b for a, b in zip(script_bytes, keystr_step)]

        # decrypt byte with key stream and write
        dec_file.write(bytes(dec_byte_step))

        # read another bytes from enc file
        script_bytes = script_file.read(N_B)


def getWholescript(args):
    '''
    Function decrypts whole script file with bruteforcing SUB vector
    :param args:
    :return:
    '''
    # open files
    plain_file = open(args.path+"/"+plaintextName, "rb")
    cipher_file = open(args.path +"/" + ciphertextName, "rb")
    script_file = open(args.path + "/" + supercipherName, "rb")
    dec_file = open(args.path + "/" + supercipherNameDec, "wb")

    # read first byte from plaintext and ciphertext
    plain_bytes = plain_file.read(N_B)
    cipher_bytes = cipher_file.read(N_B)

    # create first byte key stream
    keystr_first_byte =  [a ^ b for a, b in zip(plain_bytes, cipher_bytes)]

    # read first byte of script file
    script_bytes = script_file.read(N_B)

    # decode first byte according to first key stream
    dec_byte = [a ^ b for a, b in zip(script_bytes, keystr_first_byte)]
    dec_file.write(bytes(dec_byte))

    # read next bytes
    plain_bytes = plain_file.read(N_B)
    cipher_bytes = cipher_file.read(N_B)
    script_bytes = script_file.read(N_B)

    # next N_B bytes of key stream
    keystr_next_byte = [a ^ b for a, b in zip(plain_bytes, cipher_bytes)]
    dec_byte = [a ^ b for a, b in zip(script_bytes, keystr_next_byte)]

    # generate all combination of SUB vector
    SUBS = list(map(list, product(range(0, 2), repeat=8)))

    # try all combinations of SUB vector to obtain the same decrypted bytes as xor of plaintext and cypher text
    for SUB in SUBS:
        keystr_step = step(int.from_bytes(keystr_first_byte, 'little'), SUB).to_bytes(N_B, 'little')
        dec_byte_step = [a ^ b for a, b in zip(script_bytes, keystr_step)]

        if dec_byte == dec_byte_step:
            break

    # write decrypted bytes
    dec_file.write(bytes(dec_byte_step))

    # decrypt whole file
    decrypt(script_file, dec_file, SUB, keystr_step)

    plain_file.close()
    cipher_file.close()
    dec_file.close()
    script_file.close()

    return SUB


def getGif(args, SUB):
    '''
    Decrypt gif file using same algorithm
    :param args:
    :param SUB:
    :return:
    '''
    # open gif file and create decrypt file
    gif_file = open(args.path + "/" + hintName, "rb")
    dec_file = open(args.path + "/" + hintName[:-4], "wb")

    # read first N_B bytes
    gif_bytes = gif_file.read(N_B)

    # get first N_B bytes of key stream
    with open(args.path + "/" + plaintextName, "rb") as file:
        plain_bytes = file.read(N_B)

    with open(args.path +"/" + ciphertextName, "rb") as file:
        cipher_bytes = file.read(N_B)

    key_stream = [a ^ b for a, b in zip(plain_bytes, cipher_bytes)]

    # decrypt first N_B bytes and write
    dec_bytes = [a ^ b for a, b in zip(gif_bytes, key_stream)]
    dec_file.write(bytes(dec_bytes))

    # decrypt rest
    decrypt(gif_file, dec_file, SUB, key_stream)

    pass


def getKey(args):
    # get first N_B bytes of key stream
    with open(args.path + "/" + plaintextName, "rb") as file:
        plain_bytes = file.read(N_B)

    with open(args.path + "/" + ciphertextName, "rb") as file:
        cipher_bytes = file.read(N_B)

    key_stream = int.from_bytes(plain_bytes, 'little') ^ int.from_bytes(cipher_bytes, 'little')


    for i in range(N//2):
        key_stream = reverse_step(key_stream)

    print(key_stream.to_bytes(N_B, 'little').decode())

    pass


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str,
                        help="path to dictionary with secret files")
    args = parser.parse_args()

    getKey(args)
    pass


if __name__ == '__main__':
    main()
