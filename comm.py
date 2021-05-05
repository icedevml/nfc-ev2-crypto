import io
import struct
from enum import Enum
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def require(msg, condition):
    if not condition:
        raise RuntimeError("Condition failed: {}".format(msg))


class CommMode(Enum):
    PLAIN = 1
    MAC = 2
    FULL = 3


class BaseComm:
    def wrap_cmd(self, ins: int, mode: CommMode, header: bytes = None, data: bytes = None) -> bytes:
        """
        Wrap commend into APDU with CommMode.PLAIN/MAC/FULL
        :param ins: command code, e.g. 0x8D (ISO SELECT CC)
        :param header: command header, e.g. b"\x03\x00\x00\x00\x0A\x00\x00"
        :param data: command data, e.g. b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        :param mode: communication mode
        :return: wrapped APDU (bytes)
        """
        if header is None:
            header = b""

        if data is None:
            data = b""

        payload_len = len(header) + len(data)
        apdu = b"\x90" + bytes([ins]) + b"\x00\x00" + bytes([payload_len]) + header + data + b"\x00"

        if mode == CommMode.PLAIN:
            self.cmd_counter += 1
            return apdu
        elif mode == CommMode.MAC:
            return self.sign_apdu(apdu)
        elif mode == CommMode.FULL:
            return self.encrypt_apdu(apdu, len(header))

        raise RuntimeError("Invalid CommMode specified.")

    def sign_apdu(self, apdu: bytes) -> bytes:
        """
        Convert CommMode.PLAIN APDU into CommMode.MAC
        :param apdu: Plain APDU
        :return: Signed APDU
        """
        if self.ti is None:
            raise RuntimeError("TI was not set.")

        # [CLS=90] [INS] [P1=00] [P2=00] [Lc] [data...] [Le=0]
        require("APDU CLS=0x90", apdu[0] == 0x90)
        require("APDU P1=0x00", apdu[2] == 0x00)
        require("APDU P2=0x00", apdu[3] == 0x00)
        require("APDU Lc valid", apdu[4] == len(apdu) - 6)
        require("APDU Le=0x00", apdu[-1] == 0x00)

        cmd = apdu[1:2]
        cmd_cntr_b = struct.pack("<H", self.cmd_counter)
        ti = self.ti
        data = apdu[5:-1]
        mact = self.calc_raw_data(cmd + cmd_cntr_b + ti + data)
        new_len = bytes([apdu[4] + len(mact)])
        require("APDU Data shorter than 256 bytes", len(new_len) == 1)

        self.cmd_counter += 1
        return b"\x90" + cmd + b"\x00\x00" + new_len + data + mact + b"\x00"

    def perform_enc(self, plaintext):
        raise NotImplementedError()

    def perform_dec(self, ciphertext):
        raise NotImplementedError()

    def parse_response(self, res: bytes) -> Tuple[bytes, bytes]:
        """
        Parse and check signature for R-APDU
        :param res: R-APDU
        :return: tuple(status code, response data)
        """
        require("Response code 91xx", res[-2] == 0x91)
        status = res[-2:]
        mact = res[-10:-2]
        data = res[:-10]

        our_mact = self.calc_raw_data(status[1:2] + struct.pack("<H", self.cmd_counter) + self.ti + data)

        require("Received MAC == calculated MAC", mact == our_mact)
        return status, data

    def decrypt_response(self, data: bytes) -> bytes:
        """
        Decrypt CommMode.FULL response data
        :param data: encrypted response data returned from validate_response()
        :return: decrypted data without padding
        """
        if not len(data):
            return b""

        return unpad(self.perform_dec(data), AES.block_size, "iso7816")

    def unwrap_res(self, res: bytes, mode: CommMode) -> Tuple[bytes, bytes]:
        """
        Process response in any communication mode
        :param res: R-APDU (bytes)
        :param mode: CommMode
        :return: tuple(status, response data)
        """
        if mode == CommMode.PLAIN:
            require("Response code 91xx", res[-2] == 0x91)
            status_code = res[-2:]
            data = res[:-2]
            return status_code, data
        elif mode == CommMode.MAC:
            status_code, data = self.parse_response(res)
            return status_code, data
        elif mode == CommMode.FULL:
            status_code, enc_data = self.parse_response(res)
            return status_code, self.decrypt_response(enc_data)

    def wrap_cmd(self, ins: int, mode: CommMode, header: bytes = None, data: bytes = None) -> bytes:
        """
        Wrap commend into APDU with CommMode.PLAIN/MAC/FULL
        :param ins: command code, e.g. 0x8D (ISO SELECT CC)
        :param header: command header, e.g. b"\x03\x00\x00\x00\x0A\x00\x00"
        :param data: command data, e.g. b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        :param mode: communication mode
        :return: wrapped APDU (bytes)
        """
        if header is None:
            header = b""

        if data is None:
            data = b""

        payload_len = len(header) + len(data)
        payload_section = bytes([payload_len]) + header + data

        if payload_len == 0:
            payload_section = b""

        apdu = b"\x90" + bytes([ins]) + b"\x00\x00" + payload_section + b"\x00"

        if mode == CommMode.PLAIN:
            self.cmd_counter += 1
            return apdu
        elif mode == CommMode.MAC:
            return self.sign_apdu(apdu)
        elif mode == CommMode.FULL:
            return self.encrypt_apdu(apdu, len(header))

        raise RuntimeError("Invalid CommMode specified.")

    def sign_apdu(self, apdu: bytes) -> bytes:
        """
        Convert CommMode.PLAIN APDU into CommMode.MAC
        :param apdu: Plain APDU
        :return: Signed APDU
        """
        if self.ti is None:
            raise RuntimeError("TI was not set.")

        # [CLS=90] [INS] [P1=00] [P2=00] [Lc] [data...] [Le=0]
        require("APDU CLS=0x90", apdu[0] == 0x90)
        require("APDU P1=0x00", apdu[2] == 0x00)
        require("APDU P2=0x00", apdu[3] == 0x00)
        require("APDU Lc valid", apdu[4] == len(apdu) - 6 or len(apdu) == 5)
        require("APDU Le=0x00", apdu[-1] == 0x00)

        cmd = apdu[1:2]
        cmd_cntr_b = struct.pack("<H", self.cmd_counter)
        ti = self.ti

        if len(apdu) == 5:
            data = b""
            mact = self.calc_raw_data(cmd + cmd_cntr_b + ti)
            new_len = bytes([len(mact)])
        else:
            data = apdu[5:-1]
            mact = self.calc_raw_data(cmd + cmd_cntr_b + ti + data)
            new_len = bytes([apdu[4] + len(mact)])

        require("APDU Data shorter than 256 bytes", len(new_len) == 1)

        self.cmd_counter += 1
        return b"\x90" + cmd + b"\x00\x00" + new_len + data + mact + b"\x00"

    def encrypt_apdu(self, apdu, data_offset):
        """
        Convert CommMode.PLAIN APDU into CommMode.FULL
        :param apdu: Plain APDU
        :param data_offset: length of the command header (how many data bytes should get through unencrypted)
        :return: Encrypted APDU
        """
        require("APDU CLS=0x90", apdu[0] == 0x90)
        require("APDU P1=0x00", apdu[2] == 0x00)
        require("APDU P2=0x00", apdu[3] == 0x00)
        require("APDU Lc valid", apdu[4] == len(apdu) - 6 or len(apdu) == 5)
        require("APDU Le=0x00", apdu[-1] == 0x00)

        header = apdu[5:5 + data_offset]

        plainstream = io.BytesIO()
        plainstream.write(apdu[5+data_offset:-1])

        # don't encrypt if the command doesn't contain any data
        if len(apdu[5+data_offset:-1]) == 0:
            return self.sign_apdu(apdu)

        # byte \x80 has to be always appended by convention, even if
        # the block is already divisible by AES.block_size
        plainstream.write(b"\x80")

        # zero-pad until block is full
        while plainstream.getbuffer().nbytes % AES.block_size != 0:
            plainstream.write(b"\x00")

        enc = self.perform_enc(plainstream.getvalue())
        new_len = bytes([len(header) + len(enc)])
        require("APDU Data shorter than 256 bytes", len(new_len) == 1)
        return self.sign_apdu(b"\x90" + apdu[1:2] + b"\x00\x00" + new_len + header + enc + b"\x00")
