# Verify asymmetric originality signature
# Based on public AN12196 8.2 Asymmetric check

import sys
import binascii

from ecdsa.curves import NIST224p
PUBLIC_KEY = binascii.unhexlify(b"048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410")

def validate_tag(uid: bytes, sig: bytes) -> bool:
    vk = VerifyingKey.from_string(PUBLIC_KEY, curve=NIST224p)
    return vk.verify_digest(sig, uid)


if __name__ == "__main__":
    uid = binascii.unhexlify(sys.argv[1])
    sig = binascii.unhexlify(sys.argv[2])
    
    if len(sys.argv) != 3:
        print('Usage: python3 validate_ecc.py <uid> <sig>')
        print('Example:')
        print('    python3 validate_ecc.py 04518DFAA96180 D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21')
    
    if validate_tag(uid, sig):
        print('OK')
        sys.exit(0)
    else:
        print('INVALID')
        sys.exit(1)
