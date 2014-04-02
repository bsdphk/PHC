#!/usr/bin/env python

from Crypto.Random.random import getrandbits
from Crypto.Util.number import long_to_bytes
from binascii import hexlify

from catfish import Catfish


FILE_NAME = 'test_vectors.txt'


def main():
    from example_params import generator, modulus, bitlen_modulus, \
        prime1, prime2
    assert prime1 * prime2 == modulus

    my_catfish = Catfish(
        gen=generator,
        mod=modulus,
        len_mod=1024,
        tcost=2,
        mcost=bitlen_modulus,
        # verbose=True,
        prime1=prime1,
        prime2=prime2
    )

    with open(FILE_NAME, 'w') as f:
        for pass_len in range(128 + 1):
            salt = long_to_bytes(getrandbits(128), 128 / 8)
            if pass_len == 0:
                password = ''
            else:
                password = long_to_bytes(getrandbits(pass_len * 8), pass_len)
            tag = my_catfish.digest(salt, password)

            print 'length', pass_len
            print 'password', hexlify(password)
            print 'salt', hexlify(salt)
            print 'tag', hexlify(tag)
            print

            f.write('length ' + str(pass_len) + '\n')
            f.write('password ' + hexlify(password) + '\n')
            f.write('salt ' + hexlify(salt) + '\n')
            f.write('tag ' + hexlify(tag) + '\n')
            f.write('\n')


if __name__ == '__main__':
    main()
