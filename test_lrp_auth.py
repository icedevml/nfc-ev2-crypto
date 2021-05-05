import binascii

from lrp import AuthenticateLRP


def test_auth1_lrp():
    auth = AuthenticateLRP(b"\x00" * 16)

    # -------------------------------------------------------------------------
    # we patch generate_rnda to ensure predictable output for this test case
    # DON'T DO THIS WHEN USING ON PRODUCTION, RNDA SHOULD BE GENERATED RANDOMLY
    auth.generate_rnda = lambda: binascii.unhexlify("74D7DF6A2CEC0B72B412DE0D2B1117E6")
    # -------------------------------------------------------------------------

    assert auth.init(b"\x03") == b"\x90\x71\x00\x00\x03\x03\x01\x02\x00"

    resp = auth.part1(binascii.unhexlify("0156109A31977C855319CD4618C9D2AED291AF"))
    assert resp == binascii.unhexlify("90af00002074d7df6a2cec0b72b412de0d2b1117e6189b59dcedc31a3d3f38ef8d4810b3b400")

    comm = auth.part2(binascii.unhexlify(
        "F4FC209D9D60623588B299FA5D6B2D710125F8547D9FB8D572C90D2C2A14E2359100"))
    assert comm.ti == binascii.unhexlify("58EE9424")


def test_auth1_lrp_bad():
    auth = AuthenticateLRP(b"\x00" * 16)

    # -------------------------------------------------------------------------
    # we patch generate_rnda to ensure predictable output for this test case
    # DON'T DO THIS WHEN USING ON PRODUCTION, RNDA SHOULD BE GENERATED RANDOMLY
    auth.generate_rnda = lambda: binascii.unhexlify("74D7DF6A2CEC0B72B412DE0D2B1117E6")
    # -------------------------------------------------------------------------

    assert auth.init(b"\x03") == b"\x90\x71\x00\x00\x03\x03\x01\x02\x00"

    resp = auth.part1(binascii.unhexlify("0156109A31977C855319CD4618C9D2AED291AF"))
    assert resp == binascii.unhexlify("90af00002074d7df6a2cec0b72b412de0d2b1117e6189b59dcedc31a3d3f38ef8d4810b3b400")

    try:
        comm = auth.part2(binascii.unhexlify(
            "F4FC209D9D60623588B299FA5D6B2D710125F8547D9FB8D572C90D2C2A14E2119100"))
    except RuntimeError:
        pass  # this is OK
    else:
        raise RuntimeError("Exception was expected to appear here.")
