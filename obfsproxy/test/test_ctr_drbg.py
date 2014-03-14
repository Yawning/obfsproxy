import twisted.trial.unittest

import obfsproxy.common.ctr_drbg as ctr_drbg

import binascii
import math
import struct

class testCtrDrbg_NIST(twisted.trial.unittest.TestCase):
    """
    Use the known keystream values from the NIST SP 800-38A test
    to validate the random numbers.
    """

    key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
    iv = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    output = ("\xec\x8c\xdf\x73\x98\x60\x7c\xb0\xf2\xd2\x16\x75\xea\x9e\xa1\xe4"
              "\x36\x2b\x7c\x3c\x67\x73\x51\x63\x18\xa0\x77\xd7\xfc\x50\x73\xae"
              "\x6a\x2c\xc3\x78\x78\x89\x37\x4f\xbe\xb4\xc8\x1b\x17\xba\x6c\x44"
              "\xe8\x9c\x39\x9f\xf0\xf1\x98\xc6\xd4\x0a\x31\xdb\x15\x6c\xab\xfe")

    rng = None

    def setUp(self):
        self.rng = ctr_drbg.CtrDrbg(self.key + self.iv)

    def test_basic(self):
        """
        Ensure that the raw output of the CSPRNG matches the known values from
        SP 800-38A.  If this fails, then the AES implementation is probably
        broken.
        """

        known_value = long(binascii.hexlify(self.output), 16)
        self.assertEquals(known_value, self.rng.getrandbits(len(self.output) * 8))

    def test_uint8(self):
        """
        Test generating 8 bits at a time.
        """

        for x in self.output:
            self.assertEquals(long(ord(x)), self.rng.getrandbits(8))

    def test_uint32(self):
        """
        Test generating 32 bits at a time.
        """

        for i in range(0, len(self.output), 4):
            val = struct.unpack("!I", self.output[i:i+4])[0]
            self.assertEquals(long(val), self.rng.getrandbits(32))

    def test_pi(self):
        """
        Test generating lots of random numbers.
        """

        count = 0
        iters = 100000
        for i in xrange(iters):
            if math.pow(self.rng.random(), 2) + math.pow(self.rng.random(), 2) <= 1.0:
                count += 1

        pi = 4.0 * count / iters
        self.assertAlmostEqual(3.14, pi, places=2)

    def test_genHuge(self):
        """
        Test generating > _MAX_REQUEST_SIZE bits.

        Kind of sloppy since with a real seed, this is not guaranteed to be
        true, but we use a known key/iv so it's ok.
        """

        foo = self.rng.getrandbits(self.rng._MAX_REQUEST_SIZE * 2)
        self.assertEqual(foo.bit_length(), self.rng._MAX_REQUEST_SIZE * 2)
