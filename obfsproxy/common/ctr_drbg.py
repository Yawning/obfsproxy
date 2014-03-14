""" NIST SP 800-90A style CTR_DRBG, using CTR-AES-128. """

import obfsproxy.common.aes as aes

import binascii
import os
import random

class CtrDrbg(random.Random):
    """
    A NIST SP 800-90A style CTR_DRBG, using CTR-AES-128.
    """

    ctr = None
    request_count = 0

    _STATE_SIZE = 32
    _RESEED_INTERVAL = 1 << 48
    _MAX_REQUEST_SIZE = (1 << 19) / 8

    def seed(self, x=None):
        """
        Seed the CTR_DRBG, either with a user provided 32 byte string or
        from the OS provided cryptographic random number generator.
        """

        if x == None:
            x = os.urandom(self._STATE_SIZE)
        if len(x) != self._STATE_SIZE:
            raise ValueError('Seed length must be %d bytes' % self._STATE_SIZE)
        self.ctr = aes.AES_CTR_128(x[0:16], x[16:32])
        self.request_count = 0

    def getstate(self):
        raise NotImplementedError('getstate() is not implemented for CtrDrbg')

    def setstate(self, state):
        raise NotImplementedError('setstate() is not implemented for CtrDrbg')

    def jumpahead(self, n):
        raise NotImplementedError('jumpahead() is not implemented for CtrDrbg')

    def random(self):
        """
        Get the next random number in the range [0.0, 1.0).

        This will reseed from the OS CSPRNG if the maximum number of requests
        between reseeds will be exceeded.
        """

        # Algorithm taken from os.random.SystemRandom
        return (self.getrandbits(7 * 8) >> 3) * random.RECIP_BPF

    def getrandbits(self, k):
        """
        Get the next k random bits as a long int.

        This will reseed from the OS CSPRNG if the maximum number of requests
        between reseeds (2^48) will be exceeded.
        """

        if k <= 0:
            raise ValueError('number of bits must be greater than zero')

        ret = ''
        nr_bytes = to_gen = (k + 7) / 8
        while to_gen > 0:
            gen_sz = min(self._MAX_REQUEST_SIZE, to_gen)

            # CTR stream cipher output becomes distinguishable after a certain
            # number of bits are read, reseed from os.urandom() if we reach the
            # maximum number of requests

            self.request_count += 1
            if self.request_count > self._RESEED_INTERVAL:
                self.seed()

            ret += self.ctr.crypt(''.rjust(gen_sz, '\x00'))
            to_gen -= gen_sz
        ret = long(binascii.hexlify(ret), 16)
        return ret >> (nr_bytes * 8 - k)

ctr_drbg = CtrDrbg()
