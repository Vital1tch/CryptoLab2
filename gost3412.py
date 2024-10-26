# coding: utf-8
# PyGOST -- Pure Python GOST cryptographic functions library
# Copyright (C) 2015-2023 Sergey Matveev <stargrave@stargrave.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""GOST 34.12-2015 64 and 128 bit block ciphers (:rfc:`7801`)

Several precalculations are performed during this module importing.
"""

from gost28147 import block2ns as gost28147_block2ns
from gost28147 import decrypt as gost28147_decrypt
from gost28147 import encrypt as gost28147_encrypt
from gost28147 import ns2block as gost28147_ns2block
from utils import strxor
from utils import xrange


KEYSIZE = 32

LC = bytearray((
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
))
PI = [159, 22, 243, 168, 16, 239, 32, 153, 130, 191, 125, 220, 228, 81, 154, 143, 10,
223, 175, 253, 195, 103, 188, 189, 198, 238, 222, 240, 185, 54, 99, 47, 23, 172, 72, 53,
124, 24, 139, 67, 249, 161, 4, 149, 41, 186, 250, 132, 133, 0, 44, 51, 57, 66, 234, 200,
2, 28, 212, 187, 117, 129, 193, 237, 148, 226, 227, 242, 108, 76, 120, 146, 165, 119,
210, 169, 70, 213, 111, 21, 33, 151, 174, 26, 182, 235, 199, 95, 89, 74, 90, 17, 34, 138,
192, 8, 64, 141, 49, 155, 93, 39, 109, 65, 203, 206, 236, 255, 233, 104, 82, 83, 163,
171, 25, 245, 118, 135, 216, 101, 27, 102, 183, 68, 29, 246, 142, 43, 75, 19, 136, 80,
121, 116, 40, 181, 252, 5, 14, 42, 224, 115, 251, 209, 218, 3, 58, 244, 127, 15, 112,
180, 6, 221, 97, 1, 140, 211, 229, 46, 107, 122, 69, 254, 96, 110, 37, 184, 55, 7, 62,
123, 170, 232, 150, 147, 92, 128, 114, 77, 71, 166, 167, 207, 173, 164, 126, 177, 78,
79, 247, 157, 30, 196, 131, 225, 52, 219, 63, 156, 85, 137, 179, 241, 215, 87, 231, 214,
50, 35, 208, 134, 202, 31, 105, 11, 60, 84, 12, 100, 88, 197, 205, 36, 152, 144, 94, 18,
91, 178, 145, 106, 61, 217, 190, 86, 201, 48, 59, 13, 248, 73, 160, 113, 9, 20, 158, 230,
56, 38, 204, 45, 194, 176, 98, 162]




########################################################################
# Precalculate inverted PI value as a performance optimization.
# Actually it can be computed only once and saved on the disk.
########################################################################
PIinv = bytearray(256)
for x in xrange(256):
    PIinv[PI[x]] = x


def gf(a, b):
    c = 0
    while b:
        if b & 1:
            c ^= a
        if a & 0x80:
            a = (a << 1) ^ 0x1C3
        else:
            a <<= 1
        b >>= 1
    return c

########################################################################
# Precalculate all possible gf(byte, byte) values as a performance
# optimization.
# Actually it can be computed only once and saved on the disk.
########################################################################


GF = [bytearray(256) for _ in xrange(256)]

for x in xrange(256):
    for y in xrange(256):
        GF[x][y] = gf(x, y)


def L(blk, rounds=16):
    for _ in range(rounds):
        t = blk[15]
        for i in range(14, -1, -1):
            blk[i + 1] = blk[i]
            t ^= GF[blk[i]][LC[i]]
        blk[0] = t
    return blk


def Linv(blk):
    for _ in range(16):
        t = blk[0]
        for i in range(15):
            blk[i] = blk[i + 1]
            t ^= GF[blk[i]][LC[i]]
        blk[15] = t
    return blk

########################################################################
# Precalculate values of the C -- it does not depend on key.
# Actually it can be computed only once and saved on the disk.
########################################################################


C = []

for x in range(1, 33):
    y = bytearray(16)
    y[15] = x
    C.append(L(y))


def lp(blk):
    return L([PI[v] for v in blk])


class GOST3412Kuznechik(object):
    """GOST 34.12-2015 128-bit block cipher Кузнечик (Kuznechik)
    """
    blocksize = 16

    def __init__(self, key):
        """
        :param key: encryption/decryption key
        :type key: bytes, 32 bytes

        Key scheduling (roundkeys precomputation) is performed here.
        """
        kr0 = bytearray(key[:16])
        kr1 = bytearray(key[16:])
        self.ks = [kr0, kr1]
        for i in range(4):
            for j in range(8):
                k = lp(bytearray(strxor(C[8 * i + j], kr0)))
                kr0, kr1 = [strxor(k, kr1), kr0]
            self.ks.append(kr0)
            self.ks.append(kr1)

    def encrypt(self, blk):
        blk = bytearray(blk)
        for i in range(9):
            blk = lp(bytearray(strxor(self.ks[i], blk)))
        return bytes(strxor(self.ks[9], blk))

    def decrypt(self, blk):
        blk = bytearray(blk)
        for i in range(9, 0, -1):
            blk = [PIinv[v] for v in Linv(bytearray(strxor(self.ks[i], blk)))]
        return bytes(strxor(self.ks[0], blk))


class GOST3412Magma(object):
    """GOST 34.12-2015 64-bit block cipher Магма (Magma)
    """
    blocksize = 8

    def __init__(self, key):
        """
        :param key: encryption/decryption key
        :type key: bytes, 32 bytes
        """
        # Backward compatibility key preparation for 28147-89 key schedule
        self.key = b"".join(key[i * 4:i * 4 + 4][::-1] for i in range(8))
        self.sbox = "id-tc26-gost-28147-param-Z"

    def encrypt(self, blk):
        return gost28147_ns2block(gost28147_encrypt(
            self.sbox,
            self.key,
            gost28147_block2ns(blk[::-1]),
        ))[::-1]

    def decrypt(self, blk):
        return gost28147_ns2block(gost28147_decrypt(
            self.sbox,
            self.key,
            gost28147_block2ns(blk[::-1]),
        ))[::-1]
