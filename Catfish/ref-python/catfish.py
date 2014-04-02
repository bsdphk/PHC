#!/usr/bin/env python

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.strxor import strxor
from binascii import hexlify, unhexlify

from keccak import Keccak


def long2bytes(number, num_bytes):
    string = long_to_bytes(number, num_bytes)
    assert len(string) == num_bytes
    # reverse the string, since we are using little-endian
    string = string[::-1]
    return string


def bytes2long(string):
    string = string[::-1]
    number = bytes_to_long(string)
    return number


def extended_euclidean(a, b):
    # modified based on http://goo.gl/NoMoEJ
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return x, y


class Catfish:
    """
    Unoptimized reference code for Catfish
    """
    def __init__(self,
                 gen, mod, len_mod,
                 tcost=1, mcost=1024, hsize=256,
                 verbose=False,
                 prime1=None, prime2=None):
        assert 1 < gen < mod
        assert len_mod % 8 == 0
        # assert nbits >= 1024
        # assert mod < (1 << len_mod)
        assert tcost > 0
        assert mcost > 0
        assert hsize >= 96

        self._gen = gen  # g
        self._mod = mod  # n
        self._bitlen = len_mod  # N
        self._bytelen = self._bitlen / 8

        self._tcost = tcost
        self._mcost = mcost
        self._hsize = hsize
        self.__kclass = Keccak()

        self.verbose = verbose

        self.__fast_DL = False
        if prime1 is not None and prime2 is not None:
            assert prime1 * prime2 == mod
            self.__p = prime1
            self.__q = prime2
            x, y = extended_euclidean(prime1, prime2)
            assert (x * prime1 + y * prime2) % mod == 1
            self.__ep = x * prime1
            self.__eq = y * prime2
            self.__fast_DL = True

    def _keccak(self, msg, output_bits):
        """
        a wrapper for Keccak's reference code
        using the default values r = 1024, c = 576
        """
        len_msg = len(msg) * 8  # in bit
        hex_msg = hexlify(msg)
        hashed = self.__kclass.Keccak(
            (len_msg, hex_msg),
            n=output_bits
        )
        return unhexlify(hashed)

    def _discrete_log(self, num):
        return pow(self._gen, num, self._mod)

    def _fast_discrete_log(self, num):
        """
        use Chinese remainder theorem to speed up DL computations
        if the factorization of n, i.e. p and q, are known
        """
        rp = pow(self._gen % self.__p, num % (self.__p - 1), self.__p)
        rq = pow(self._gen % self.__q, num % (self.__q - 1), self.__q)
        res = (rp * self.__eq + rq * self.__ep) % self._mod
        # assert res == self._discrete_log(num)
        return res

    def _H(self, state):
        state = self._keccak(state, self._bitlen)
        number = bytes2long(state)
        if self.__fast_DL:
            number = self._fast_discrete_log(number)
        else:
            number = self._discrete_log(number)
        state = long2bytes(number, self._bytelen)
        return state

    def digest(self, salt, password):
        assert len(salt) == 128 / 8  # in byte
        assert len(password) <= 128

        v = [None] * self._mcost

        ctr = 0
        x = salt \
            + long2bytes(len(password) * 8, 128 / 8) \
            + password.ljust(128, '\x00')
        # print hexlify(x)

        for i in xrange(self._tcost):
            if self.verbose:
                print 'tcost round', i

            x = self._H(x)
            # print hexlify(x)

            for j in xrange(self._mcost):
                v[j] = x
                ctr += 1
                x = strxor(x, long2bytes(ctr, self._bytelen))
                x = self._H(x)
            for j in xrange(self._mcost):
                k = bytes2long(x) % self._mcost
                x = strxor(x, v[k])
                ctr += 1
                x = strxor(x, long2bytes(ctr, self._bytelen))
                x = self._H(x)
            ctr += 1

        # print hexlify(x)

        x = strxor(x, long2bytes(ctr, self._bytelen))
        tag = self._keccak(x, self._hsize)
        return tag

    def hexdigest(self, salt, password):
        return hexlify(self.digest(salt, password))


def main():
    # prime1 = int(
    #     '102639592829741105772054196573991675900' +
    #     '716567808038066803341933521790711307779')
    # prime2 = int(
    #     '1066034883801684548209272203600128786792' +
    #     '07958575989291522270608237193062808643')
    # modulus = prime1 * prime2

    from example_params import generator, modulus, bitlen_modulus, \
        prime1, prime2
    assert prime1 * prime2 == modulus

    catfish = Catfish(
        gen=generator,
        mod=modulus,
        len_mod=1024,
        tcost=2,
        mcost=bitlen_modulus,
        verbose=True,
        prime1=prime1,
        prime2=prime2
    )

    # from Crypto.Random.random import getrandbits
    # salt = long2bytes(getrandbits(128), 128 / 8)
    hexsalt = '4c880aa553669c3869f62b389c2c3499'
    salt = unhexlify(hexsalt)
    password = 'The quick brown fox jumps over the lazy dog'

    print 'hexsalt', hexlify(salt)
    print 'pass', password
    print 'hexpass', hexlify(password)
    hextag = catfish.hexdigest(salt, password)
    print 'hexhash', hextag


if __name__ == '__main__':
    main()
