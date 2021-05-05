# AN12196 Section 6.6 Page 28
# Authorization with key 0x00
import binascii

from comm import CommMode
from ev2 import AuthenticateEV2, CryptoComm


def test_auth1():
    auth = AuthenticateEV2(b"\x00" * 16)

    # -------------------------------------------------------------------------
    # we patch generate_rnda to ensure predictable output for this test case
    # DON'T DO THIS WHEN USING ON PRODUCTION, RNDA SHOULD BE GENERATED RANDOMLY
    auth.generate_rnda = lambda: b"\x13\xC5\xDB\x8A\x59\x30\x43\x9F\xC3\xDE\xF9\xA4\xC6\x75\x36\x0F"
    # -------------------------------------------------------------------------

    assert auth.init(b"\x00") == b"\x90\x71\x00\x00\x02\x00\x00\x00"

    resp = auth.part1(b"\xA0\x4C\x12\x42\x13\xC1\x86\xF2\x23\x99\xD3\x3A\xC2\xA3\x02\x15\x91\xAF")
    assert resp == binascii.unhexlify("90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00")

    comm = auth.part2(
        b"\x3F\xA6\x4D\xB5\x44\x6D\x1F\x34\xCD\x6E\xA3\x11\x16\x7F\x5E\x49"
        b"\x85\xB8\x96\x90\xC0\x4A\x05\xF1\x7F\xA7\xAB\x2F\x08\x12\x06\x63"
        b"\x91\x00")
    assert comm.ti == binascii.unhexlify("9d00c4df")
    assert comm.pdcap2 == binascii.unhexlify("000000000000")
    assert comm.pcdcap2 == binascii.unhexlify("000000000000")
    assert comm.k_ses_auth_enc == binascii.unhexlify("1309C877509E5A215007FF0ED19CA564")
    assert comm.k_ses_auth_mac == binascii.unhexlify("4C6626F5E72EA694202139295C7A7FC7")


def test_auth2():
    # AN12196 Section 6.10 Page 34
    # Authorization with key 0x03
    auth = AuthenticateEV2(b"\x00" * 16)

    # -------------------------------------------------------------------------
    # we patch generate_rnda to ensure predictable output for this test case
    # DON'T DO THIS WHEN USING ON PRODUCTION, RNDA SHOULD BE GENERATED RANDOMLY
    auth.generate_rnda = lambda: binascii.unhexlify("B98F4C50CF1C2E084FD150E33992B048")
    # -------------------------------------------------------------------------

    assert auth.init(b"\x00") == b"\x90\x71\x00\x00\x02\x00\x00\x00"

    resp = auth.part1(binascii.unhexlify("B875CEB0E66A6C5CD00898DC371F92D191AF"))
    assert resp == binascii.unhexlify("90AF000020FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B100")

    comm = auth.part2(
        binascii.unhexlify("0CC9A8094A8EEA683ECAAC5C7BF20584206D0608D477110FC6B3D5D3F65C3A6A9100"))
    assert comm.ti == binascii.unhexlify("7614281A")
    assert comm.pdcap2 == binascii.unhexlify("000000000000")
    assert comm.pcdcap2 == binascii.unhexlify("000000000000")
    assert comm.k_ses_auth_enc == binascii.unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4")
    assert comm.k_ses_auth_mac == binascii.unhexlify("FC4AF159B62E549B5812394CAB1918CC")


def test_mac1():
    # AN12196 Section 5.3 Page 21
    # Command/Response in CommMode.MAC
    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("8248134A386E86EB7FAF54A52E536CB6"))
    mact = m.calc_raw_data(binascii.unhexlify("F500007A21085E02"))
    assert mact == binascii.unhexlify("6597A457C8CD442C")

    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("8248134A386E86EB7FAF54A52E536CB6"),
                   ti=b"\x7A\x21\x08\x5E",
                   cmd_counter=0)
    # convert from CommMode.PLAIN to CommMode.MAC
    assert m.sign_apdu(b"\x90\xF5\x00\x00\x01\x02\x00") == binascii.unhexlify("90F5000009026597A457C8CD442C00")

    # seems like SW1=91 at the beginning was omitted in the example, added it by hand
    status_code, data = m.parse_response(
        binascii.unhexlify("0040EEEE000100D1FE001F00004400004400002000006A00002A474282E7A479869100"))
    assert status_code.hex() == "9100"
    assert data.hex() == "0040eeee000100d1fe001f00004400004400002000006a0000"


def test_full1():
    # AN12196 Section 5.4 Page 22
    # Command data in CommMode.FULL
    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("4C6626F5E72EA694202139295C7A7FC7"),
                   k_ses_auth_enc=binascii.unhexlify("1309C877509E5A215007FF0ED19CA564"),
                   ti=binascii.unhexlify("9D00C4DF"),
                   cmd_counter=0)

    # this command takes ordinary plain APDU and turns it into CommMode.FULL encrypted one
    # the example of plain APDU was not taken from the docs but rather written by hand
    # notice data_offset=7 - this is to specify where is the boundary between command header and command data,
    # just because header gets through unencrypted
    apdu = binascii.unhexlify(
        "908D000087020000008000000051D1014D550463686F6F73652E75726C2E636F"
        "6D2F6E7461673432343F653D3030303030303030303030303030303030303030"
        "30303030303030303030303026633D3030303030303030303030303030303000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000")
    res = m.encrypt_apdu(apdu, data_offset=7)
    # check whether we arrived at the same result as in docs
    proper = binascii.unhexlify(
        "908D00009F02000000800000421C73A27D827658AF481FDFF20A5025B559D0E3"
        "AA21E58D347F343CFFC768BFE596C706BC00F2176781D4B0242642A0FF5A42C4"
        "61AAF894D9A1284B8C76BCFA658ACD40555D362E08DB15CF421B51283F9064BC"
        "BE20E96CAE545B407C9D651A3315B27373772E5DA2367D2064AE054AF996C6F1"
        "F669170FA88CE8C4E3A4A7BBBEF0FD971FF532C3A802AF745660F2B4D1D9A849"
        "9661EBF300")
    assert res == proper

    status_code, data = m.parse_response(binascii.unhexlify("FC222E5F7A5424529100"))
    assert status_code == b"\x91\x00"
    assert data == b""


def test_full2():
    # AN12196 Section 6.12 Page 36
    m = CryptoComm(
        k_ses_auth_mac=binascii.unhexlify("FC4AF159B62E549B5812394CAB1918CC"),
        k_ses_auth_enc=binascii.unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4"),
        ti=binascii.unhexlify("7614281A"),
        cmd_counter=0)
    apdu = binascii.unhexlify("908D000011030000000A00000102030405060708090A00")
    # convert CommMode.PLAIN into CommMode.FULL
    res = m.encrypt_apdu(apdu, data_offset=7)
    # compare with docs
    proper = binascii.unhexlify(
        "908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00")
    assert res == proper

    status_code, data = m.parse_response(binascii.unhexlify("C26D236E4A7C046D9100"))
    assert status_code == b"\x91\x00"
    assert data == b""


def test_full3():
    # AN12196 Section 7.3 Page 43
    # Response data in CommMode.FULL
    m = CryptoComm(
        k_ses_auth_mac=binascii.unhexlify("379D32130CE61705DD5FD8C36B95D764"),
        k_ses_auth_enc=binascii.unhexlify("2B4D963C014DC36F24F69A50A394F875"),
        ti=binascii.unhexlify("DF055522"))

    apdu = binascii.unhexlify("905100000000")
    res = m.encrypt_apdu(apdu, data_offset=0)
    proper = binascii.unhexlify("90510000088E2C155ADDA99BE300")
    assert res == proper

    # first let's validate MAC and extract the encrypted data from APDU as we would do with CommMode.MAC
    status_code, data = m.parse_response(
        binascii.unhexlify("70756055688505B52A5E26E59E329CD6595F672298EA41B79100"))
    assert status_code == binascii.unhexlify("9100")
    assert data == binascii.unhexlify("70756055688505B52A5E26E59E329CD6")
    # if we arrived here, the MACt signature seems to be valid, let's decrypt the response data
    assert m.decrypt_response(data) == binascii.unhexlify("04958CAA5C5E80")


def test_wrap_cmd1():
    # similar to test_full2 but with additional convenience wrapper
    # AN12196 Section 6.12 Page 36
    m = CryptoComm(
        k_ses_auth_mac=binascii.unhexlify("FC4AF159B62E549B5812394CAB1918CC"),
        k_ses_auth_enc=binascii.unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4"),
        ti=binascii.unhexlify("7614281A"),
        cmd_counter=0)

    res = m.wrap_cmd(0x8D,
                     mode=CommMode.FULL,
                     header=b"\x03\x00\x00\x00\x0A\x00\x00",
                     data=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A")
    assert res == binascii.unhexlify(
        "908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00")

    status_code, data = m.unwrap_res(binascii.unhexlify("C26D236E4A7C046D9100"), CommMode.FULL)
    assert status_code == b"\x91\x00"
    assert data == b""


def test_wrap_cmd2():
    # similar to test_mac1 but with additional convenience wrapper
    # AN12196 Section 5.3 Page 21
    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("8248134A386E86EB7FAF54A52E536CB6"),
                   ti=b"\x7A\x21\x08\x5E",
                   cmd_counter=0)
    assert m.wrap_cmd(0xF5, mode=CommMode.MAC, header=b"\x02") \
        == binascii.unhexlify("90F5000009026597A457C8CD442C00")

    status_code, data = m.unwrap_res(
        binascii.unhexlify("0040EEEE000100D1FE001F00004400004400002000006A00002A474282E7A479869100"),
        CommMode.MAC)
    assert status_code.hex() == "9100"
    assert data.hex() == "0040eeee000100d1fe001f00004400004400002000006a0000"


def test_wrap_cmd3():
    # AN12196 Section 7.3 Page 43
    # similar to test_full3 but with additional convenience wrapper
    m = CryptoComm(
        k_ses_auth_mac=binascii.unhexlify("379D32130CE61705DD5FD8C36B95D764"),
        k_ses_auth_enc=binascii.unhexlify("2B4D963C014DC36F24F69A50A394F875"),
        ti=binascii.unhexlify("DF055522"))

    res = m.wrap_cmd(0x51, CommMode.FULL)
    proper = binascii.unhexlify("90510000088E2C155ADDA99BE300")
    assert res == proper

    # first let's validate MAC and extract the encrypted data from APDU as we would do with CommMode.MAC
    status_code, data = m.unwrap_res(
        binascii.unhexlify("70756055688505B52A5E26E59E329CD6595F672298EA41B79100"),
        CommMode.FULL)
    assert status_code == binascii.unhexlify("9100")
    # with the convenience wrapper data is already decrypted here
    assert data == binascii.unhexlify("04958CAA5C5E80")
