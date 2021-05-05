"""
Leakage Resilient Primitive (AN12304).

NOTE: This implementation is suitable only for use on PCD side (the device which reads/interacts with the NFC tag).
You shouldn't use this code on PICC (NFC tag/card) side and it shouldn't be ported to JavaCards or similar,
because in such case it may be not resistant to the side channel attacks.
"""

import binascii
import io
import os
import struct
from typing import Generator, List, Union, Tuple

from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import _Element
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

from comm import require, BaseComm, CommMode


def remove_pad(pt: bytes):
    padl = 0

    for b in pt[::-1]:
        padl += 1

        if b == 0x80:
            break

        if b != 0x00:
            raise RuntimeError('Invalid padding')

    return pt[:-padl]


def nibbles(x: Union[bytes, str]) -> Generator[int, None, None]:
    """
    Generate integers out of x (bytes), applicable for m = 4
    """
    if isinstance(x, bytes):
        x = x.hex()

    for nb in x:
        yield binascii.unhexlify("0" + nb)[0]


def incr_counter(r: bytes):
    max_bit_len = len(r) * 8

    ctr_orig = int.from_bytes(r, byteorder='big', signed=False)
    ctr_incr = ctr_orig + 1

    if ctr_incr.bit_length() > max_bit_len:
        # we have overflow, reset counter to zero
        return b"\x00" * len(r)

    return ctr_incr.to_bytes(len(r), byteorder='big')


def e(k: bytes, v: bytes) -> bytes:
    """
    Simple AES/ECB encrypt `v` with key `k`
    """
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.encrypt(v)


def d(k: bytes, v: bytes) -> bytes:
    """
    Simple AES/ECB decrypt `v` with key `k`
    """
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.decrypt(v)


class LRP:
    def __init__(self, key: bytes, u: int, r: bytes = None, pad: bool = True):
        """
        Leakage Resilient Primitive
        :param key: secret key from which updated keys will be derived
        :param u: number of updated key to use (counting from 0)
        :param r: IV/counter value (default: all zeros)
        :param pad: whether to use bit padding or no (default: True)
        """
        if r is None:
            r = b"\x00" * 16

        self.key = key
        self.u = u
        self.r = r
        self.pad = pad

        self.p = LRP.generate_plaintexts(key)
        self.ku = LRP.generate_updated_keys(key)
        self.kp = self.ku[self.u]

    @staticmethod
    def generate_plaintexts(k: bytes, m: int = 4) -> List[bytes]:
        """
        Algorithm 1
        """
        h = k
        h = e(h, b"\x55" * 16)
        p = []

        for i in range(0, 2**m):
            p.append(e(h, b"\xaa" * 16))
            h = e(h, b"\x55" * 16)

        return p

    @staticmethod
    def generate_updated_keys(k: bytes, q: int = 4) -> List[bytes]:
        """
        Algorithm 2
        """
        h = k
        h = e(h, b"\xaa" * 16)
        uk = []

        for i in range(0, q):
            uk.append(e(h, b"\xaa" * 16))
            h = e(h, b"\x55" * 16)

        return uk

    @staticmethod
    def eval_lrp(p: List[bytes], kp: bytes, x: Union[bytes, str], final: bool) -> bytes:
        """
        Algorithm 3 assuming m = 4
        """
        y = kp

        for x_i in nibbles(x):
            p_j = p[x_i]
            y = e(y, p_j)

        if final:
            y = e(y, b"\x00" * 16)

        return y

    def encrypt(self, data: bytes) -> bytes:
        """
        LRICB encrypt and update counter (LRICBEnc)
        :param data: plaintext
        :return: ciphertext
        """
        ptstream = io.BytesIO()
        ctstream = io.BytesIO()
        ptstream.write(data)

        if self.pad:
            ptstream.write(b"\x80")

            while ptstream.getbuffer().nbytes % AES.block_size != 0:
                ptstream.write(b"\x00")
        elif ptstream.getbuffer().nbytes % AES.block_size != 0:
            raise RuntimeError("Parameter pt must have length multiple of AES block size.")
        elif ptstream.getbuffer().nbytes == 0:
            raise RuntimeError("Zero length pt not supported.")

        ptstream.seek(0)

        while True:
            block = ptstream.read(AES.block_size)

            if not len(block):
                break

            y = LRP.eval_lrp(self.p, self.kp, self.r, final=True)
            ctstream.write(e(y, block))
            self.r = incr_counter(self.r)

        return ctstream.getvalue()

    def decrypt(self, data: bytes) -> bytes:
        """
        LRICB decrypt and update counter (LRICBDecs)
        :param data: ciphertext
        :return: plaintext
        """
        ctstream = io.BytesIO()
        ctstream.write(data)
        ctstream.seek(0)

        ptstream = io.BytesIO()

        while True:
            block = ctstream.read(AES.block_size)

            if not len(block):
                break

            y = LRP.eval_lrp(self.p, self.kp, self.r, final=True)
            ptstream.write(d(y, block))
            self.r = incr_counter(self.r)

        pt = ptstream.getvalue()

        if self.pad:
            pt = remove_pad(pt)

        return pt

    def cmac(self, data: bytes) -> bytes:
        """
        Calculate CMAC_LRP
        (Huge thanks to @Pharisaeus for help with polynomial math.)
        :param data: message to be authenticated
        :return: CMAC result
        """
        stream = io.BytesIO(data)

        k0 = LRP.eval_lrp(self.p, self.kp, b"\x00" * 16, True)
        k1 = (_Element(k0) * _Element(2)).encode()
        k2 = (_Element(k0) * _Element(4)).encode()

        y = b"\x00" * AES.block_size

        while True:
            x = stream.read(AES.block_size)

            if len(x) < AES.block_size or stream.tell() == stream.getbuffer().nbytes:
                break

            y = strxor(x, y)
            y = LRP.eval_lrp(self.p, self.kp, y, True)

        pad_bytes = 0

        if len(x) < AES.block_size:
            pad_bytes = AES.block_size - len(x)
            x = x + b"\x80" + (b"\x00" * (pad_bytes - 1))

        y = strxor(x, y)

        if not pad_bytes:
            y = strxor(y, k1)
        else:
            y = strxor(y, k2)

        return LRP.eval_lrp(self.p, self.kp, y, True)


class AuthenticateLRP:
    def __init__(self, auth_key):
        self.auth_key = auth_key

        self.rnda = None
        self.rndb = None

    def init(self, key_no: bytes) -> bytes:
        return b"\x90\x71\x00\x00\x03" + key_no + b"\x01\x02\x00"

    def generate_rnda(self):
        return os.urandom(16)

    def part1(self, part1_resp: bytes) -> bytes:
        require("R-APDU length", len(part1_resp) == 19)
        require("status code 91AF", part1_resp[-2:] == b"\x91\xAF")
        require("Auth mode = 01", part1_resp[0:1] == b"\x01")

        self.rndb = part1_resp[1:17]
        self.rnda = self.generate_rnda()

        sv = lrp_gen_sv(self.rnda, self.rndb)
        crypto_macing, crypto_encing = lrp_get_crypto(self.auth_key, sv)
        pcd_resp = crypto_macing.cmac(self.rnda + self.rndb)

        return b"\x90\xAF\x00\x00\x20" + self.rnda + pcd_resp + b"\x00"

    def part2(self, part2_resp: bytes) -> 'CryptoCommLRP':
        # F4FC209D9D60623588B299FA5D6B2D710125F8547D9FB8D572C90D2C2A14E2359100
        require("R-APDU length", len(part2_resp) == 34)
        require("status code 9100", part2_resp[-2:] == b"\x91\x00")
        picc_data, picc_response = part2_resp[0:16], part2_resp[16:32]

        sv = lrp_gen_sv(self.rnda, self.rndb)
        print('auth key', self.auth_key.hex())
        print('sv', sv.hex())
        crypto_macing, crypto_encing = lrp_get_crypto(self.auth_key, sv)
        dec_picc_data = crypto_encing.decrypt(picc_data)

        require("generated PICCResponse == received PICCResponse",
                crypto_macing.cmac(self.rndb + self.rnda + picc_data) == picc_response)

        comm = CryptoCommLRP(crypto_macing, crypto_encing, ti=dec_picc_data[0:4], cmd_counter=1)
        comm.cmd_counter = 0
        return comm


def lrp_gen_sv(rnda, rndb):
    stream = io.BytesIO()
    # they are counting from right to left :D
    stream.write(b"\x00\x01\x00\x80")
    stream.write(rnda[0:2])  # [RndA[15:14]
    stream.write(strxor(rnda[2:8], rndb[0:6]))  # [ (RndA[13:8] ⊕ RndB[15:10]) ]
    stream.write(rndb[-10:])  # [RndB[9:0]
    stream.write(rnda[-8:])  # RndA[7:0]
    stream.write(b"\x96\x69")
    return stream.getvalue()


def lrp_get_crypto(key, sv):
    crypto = LRP(key, 0)
    ses_auth_master_key = crypto.cmac(sv)

    crypto_macing = LRP(ses_auth_master_key, 0)
    crypto_encing = LRP(ses_auth_master_key, 1, r=b"\x00\x00\x00\x00", pad=False)
    return crypto_macing, crypto_encing


class CryptoCommLRP(BaseComm):
    """
    This class represents an authenticated session after AuthentivateEV2 command.
    It offers the ability to prepare APDUs for CommMode.MAC or CommMode.FULL and validate R-APDUs in these modes.
    """

    def __init__(self, crypto_macing,
                 crypto_encing,
                 *,
                 ti: bytes = None,
                 cmd_counter: int = 0,
                 pdcap2: bytes = None,
                 pcdcap2: bytes = None):
        self.crypto_macing = crypto_macing
        self.crypto_encing = crypto_encing
        self.ti = ti
        self.cmd_counter = cmd_counter
        self.pdcap2 = pdcap2
        self.pcdcap2 = pcdcap2

    def calc_raw_data(self, data: bytes) -> bytes:
        """
        Calculate CMAC for raw data.
        :param data: raw data
        :return: CMAC
        """
        mac = self.crypto_macing.cmac(data)
        return bytes(bytearray([mac[i] for i in range(16) if i % 2 == 1]))

    def perform_enc(self, plaintext):
        return self.crypto_encing.encrypt(plaintext)

    def perform_dec(self, ciphertext):
        return self.crypto_encing.decrypt(ciphertext)


__all__ = ['LRP', 'AuthenticateLRP', 'CryptoCommLRP']
