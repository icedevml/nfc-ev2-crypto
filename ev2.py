"""
This code was implemented based on AN12196.
"""
import binascii
import io
import os
import struct
from enum import Enum
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import unpad

from comm import BaseComm, require


def byte_rot_left(x):
    return x[1:] + x[0:1]


def byte_rot_right(x):
    return x[-1:] + x[:-1]


class AuthenticateEV2:
    """
    Perform AuthenticateEV2First handshake with the specified authorization key.
    """

    def __init__(self, auth_key):
        self.auth_key = auth_key

        self.rnda = None
        self.rndb = None

    def init(self, key_no: bytes) -> bytes:
        """
        Generate the initial APDU to begin authentication process.
        :param key_no: key number (one byte)
        :return: initial C-APDU
        """
        # [KeyNo] [LenCap]
        params = key_no + b"\x00"
        return b"\x90\x71\x00\x00\x02" + params + b"\x00"

    def generate_rnda(self):
        return os.urandom(16)

    def part1(self, part1_resp: bytes) -> bytes:
        """
        Take the first R-APDU and generate the response.
        :param part1_resp: first R-APDU (response to init())
        :return: response C-APDU
        """
        require("R-APDU length", len(part1_resp) == 18)
        require("status code 91AF", part1_resp[-2:] == b"\x91\xAF")
        rndb_enc = part1_resp[:16]

        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        self.rndb = cipher.decrypt(rndb_enc)
        self.rnda = self.generate_rnda()
        rndb_p = byte_rot_left(self.rndb)
        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        resp = cipher.encrypt(self.rnda + rndb_p)
        part2_cmd = b"\x90\xAF\x00\x00\x20" + resp + b"\x00"
        return part2_cmd

    def part2(self, part2_resp: bytes) -> 'CryptoComm':
        """
        Validate final R-APDU and create secure messaging object
        :param part2_resp: final R-APDU
        :return: CryptoComm object
        """
        require("R-APDU length", len(part2_resp) == 34)
        require("status code 9100", part2_resp[-2:] == b"\x91\x00")
        enc = part2_resp[:32]

        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        resp = cipher.decrypt(enc)
        resp_s = io.BytesIO(resp)
        ti = resp_s.read(4)
        rnda_p = resp_s.read(16)
        pdcap2 = resp_s.read(6)
        pcdcap2 = resp_s.read(6)
        recv_rnda = byte_rot_right(rnda_p)
        require("generated RndA == decrypted RndA", recv_rnda == self.rnda)

        stream = io.BytesIO()
        # they are counting from right to left :D
        stream.write(self.rnda[0:2])  # [RndA[15:14]
        stream.write(strxor(self.rnda[2:8], self.rndb[0:6]))  # [ (RndA[13:8] ⊕ RndB[15:10]) ]
        stream.write(self.rndb[-10:])  # [RndB[9:0]
        stream.write(self.rnda[-8:])  # RndA[7:0]
        # just took me an hour or two to brute force it from the examples

        sv1stream = io.BytesIO()
        sv1stream.write(b"\xA5\x5A\x00\x01\x00\x80")
        sv1stream.write(stream.getvalue())
        sv1 = sv1stream.getvalue()

        sv2stream = io.BytesIO()
        sv2stream.write(b"\x5A\xA5\x00\x01\x00\x80")
        sv2stream.write(stream.getvalue())
        sv2 = sv2stream.getvalue()

        c = CMAC.new(self.auth_key, ciphermod=AES)
        c.update(sv1)
        k_ses_auth_enc = c.digest()

        c = CMAC.new(self.auth_key, ciphermod=AES)
        c.update(sv2)
        k_ses_auth_mac = c.digest()

        return CryptoComm(k_ses_auth_mac, k_ses_auth_enc, ti=ti, pdcap2=pdcap2, pcdcap2=pcdcap2)


class CryptoComm(BaseComm):
    """
    This class represents an authenticated session after AuthentivateEV2 command.
    It offers the ability to prepare APDUs for CommMode.MAC or CommMode.FULL and validate R-APDUs in these modes.
    """

    def __init__(self, k_ses_auth_mac: bytes,
                 k_ses_auth_enc: bytes = None,
                 *,
                 ti: bytes = None,
                 cmd_counter: int = 0,
                 pdcap2: bytes = None,
                 pcdcap2: bytes = None):
        self.k_ses_auth_mac = k_ses_auth_mac
        self.k_ses_auth_enc = k_ses_auth_enc
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
        c = CMAC.new(self.k_ses_auth_mac, ciphermod=AES)
        c.update(data)
        mac = c.digest()
        return bytes(bytearray([mac[i] for i in range(16) if i % 2 == 1]))

    def perform_enc(self, plaintext):
        iv_b = b"\xA5\x5A" + self.ti + struct.pack("<H", self.cmd_counter) + 8 * b"\x00"
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_ECB)
        iv = cipher.encrypt(iv_b)

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, IV=iv)
        return cipher.encrypt(plaintext)

    def perform_dec(self, ciphertext):
        iv_b = b"\x5A\xA5" + self.ti + struct.pack("<H", self.cmd_counter) + 8 * b"\x00"
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_ECB)
        iv = cipher.encrypt(iv_b)

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, IV=iv)
        return cipher.decrypt(ciphertext)
