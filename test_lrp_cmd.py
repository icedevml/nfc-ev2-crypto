import binascii

from lrp import CryptoCommLRP, lrp_get_crypto, incr_counter
from comm import CommMode


def test_lrp_cmd():
    auth_key = binascii.unhexlify("00000000000000000000000000000000")
    sv = binascii.unhexlify("00010080993c4eed466bfc0e7ee1d30c1ebd0dea6f6481e0d70e9a174e789669")

    crypto_macing, crypto_encing = lrp_get_crypto(auth_key, sv)
    # because we are already past authentication stage so one block was processed
    crypto_encing.r = incr_counter(crypto_encing.r)
    comm = CryptoCommLRP(crypto_macing, crypto_encing, ti=binascii.unhexlify("4f5e8407"))

    assert comm.wrap_cmd(0x51, mode=CommMode.FULL) == binascii.unhexlify("9051000008c37d6270f674cc6d00")
    res = comm.unwrap_res(binascii.unhexlify("5ec351196b8e2943db04fcd4a952f53da2830dc2258e45399100"), mode=CommMode.FULL)
    assert res[0] == b"\x91\x00"
    assert res[1] == b"\x04\x94\x0d\x2a\x2f\x70\x80"

    assert comm.wrap_cmd(0x51, mode=CommMode.FULL) == binascii.unhexlify("9051000008d65ccb81e559140000")
    res = comm.unwrap_res(binascii.unhexlify("d80b735f7b4c8e7e8a3cdaaa4410f35f752769c8ebc48e1a9100"), mode=CommMode.FULL)
    assert res[0] == b"\x91\x00"
    assert res[1] == b"\x04\x94\x0d\x2a\x2f\x70\x80"

    assert comm.wrap_cmd(0x51, mode=CommMode.FULL) == binascii.unhexlify("90510000088c677d7dcc34937100")
    res = comm.unwrap_res(binascii.unhexlify("9ccd031474a50199c696d8ef272e231a10173faf41b614e49100"), mode=CommMode.FULL)
    assert res[0] == b"\x91\x00"
    assert res[1] == b"\x04\x94\x0d\x2a\x2f\x70\x80"


def test_lrp_cmd2():
    auth_key = binascii.unhexlify("00000000000000000000000000000000")
    sv = binascii.unhexlify("0001008008a6953c60bc3d34e53766689732e2a203ff23855751d644ed519669")

    crypto_macing, crypto_encing = lrp_get_crypto(auth_key, sv)
    # because we are already past authentication stage so one block was processed
    crypto_encing.r = incr_counter(crypto_encing.r)
    comm = CryptoCommLRP(crypto_macing, crypto_encing, ti=binascii.unhexlify("204f2276"))

    wrapped = comm.wrap_cmd(0x8D, header=b"\x03\x00\x00\x00\x03\x00\x00", data=b"\x01\x02\x03", mode=CommMode.FULL)
    assert wrapped == binascii.unhexlify("908d00001f03000000030000eaf0fad0430ecdc947a822e12ec8d5f3bb75f218b405fdbc00")
    resp = binascii.unhexlify("d5b8d8f8cd67f23c9100")
    res = comm.unwrap_res(resp, mode=CommMode.FULL)
    assert res[0] == b"\x91\x00"

    wrapped = comm.wrap_cmd(0xAD, header=b"\x03\x00\x00\x00\x03\x00\x00", mode=CommMode.FULL)
    assert wrapped == binascii.unhexlify("90ad00000f0300000003000059858e133a7f487d00")
    resp = binascii.unhexlify("39665fae8af18feb23da1767eaf2274bb97fc66cc94377139100")
    res = comm.unwrap_res(resp, mode=CommMode.FULL)
    assert res[0] == b"\x91\x00"
    assert res[1] == b"\x01\x02\x03"
