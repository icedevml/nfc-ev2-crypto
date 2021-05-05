# EV2/LRP cryptography example

* `AuthenticateEV2` - perform authentication with PICC using EV2 mode;
* `CryptoComm` - sign/encrypt APDUs and validate responses (EV2 mode);
* `LRP` - perform CTR mode encryption/decryption or CMACing with Leakage Resilient Primitive;
* `AuthenticateLRP` - perform authentication with PICC using LRP;
* `CryptoCommLRP` - sign/encrypt APDUs and validate responses (LRP mode);
* `validate_ecc` - check asymmetric originality signature;

This code was written according to the publicly available application note *AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints"*.

**Pull requests welcome.**

*Note: NTAG — is a trademark of NXP B.V.*

*Note: This GitHub project is not affiliated with NXP B.V. in any way. Product names are mentioned here in order to inform about compatibility.**

## Usage
### Pre-requirements
```
apt-get install -y python3 python3-pip git
git clone https://github.com/icedevml/nfc-ev2-crypto.git
cd nfc-ev2-crypto
pip3 install -r requirements.txt
```

### EV2
Please refer to `test_ev2.py` and cross-check it with the application notes. There are also some docstrings in the `ev2.py` file.

* `AuthenticateEV2` - helper for performing `AuthenticateEV2First` handshake with PICC:
  * `init` - generate the initial C-APDU to start authentication;
  * `part1` - generate a response to first R-APDU from PICC;
  * `part2` - verify second R-APDU from PICC, initialize authenticated session;
* `CryptoComm` - a class which represents "authenticated session":
  * `wrap_cmd` - construct C-APDU in given `CommMode`, convenience wrapper;
  * `unwrap_res` - parse R-APDU in given `CommMode`, convenience wrapper;
  * `sign_apdu` - convert `CommMode.PLAIN` C-APDU into `CommMode.MAC`;
  * `encrypt_apdu` - convert `CommMode.PLAIN` C-APDU into `CommMode.FULL`;
  * `parse_response` - parse R-APDU and verify it's MAC signature (`CommMode.MAC` response);
  * `decrypt_response` - decrypt the response data parsed by `validate_response` (`CommMode.FULL` response);

### LRP
Please refer to `test_lrp_cmd.py`.

### LRP Privimites

LRICB Encryption (LRICBEnc) and decryption (LRICBDec):
```python
from lrp import LRP

import binascii

# the original key
key = binascii.unhexlify("E0C4935FF0C254CD2CEF8FDDC32460CF")
# plaintext data to encrypt
pt = binascii.unhexlify("012D7F1653CAF6503C6AB0C1010E8CB0")
# also sometimes called "counter"
iv = binascii.unhexlify("C3315DBF")

# encrypt plaintext
lrp = LRP(key, 0, iv, pad=True)
ct = lrp.encrypt(pt)

# decrypt the stuff back
lrp = LRP(key, 0, iv, pad=True)
pt = lrp.decrypt(ct)
```

MACing (LRP-CMAC/CMAC_LRP):
```python
from lrp import LRP

import binascii

key = binascii.unhexlify("8195088CE6C393708EBBE6C7914ECB0B")
lrp = LRP(key, 0)
mac = lrp.cmac(binascii.unhexlify("BBD5B85772C7"))
```

Decrypt SDM PICCData and validate CMAC:

See [test_lrp_sdm.py](https://github.com/icedevml/nfc-ev2-crypto/blob/master/test_lrp_sdm.py) for an example.

### Originality check
Standalone program:

```
python3 validate_ecc.py 04518DFAA96180 D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21
```

From Python:
```python
import binascii

from validate_ecc import validate_tag

uid = binascii.unhexlify("04518DFAA96180")
sig = binascii.unhexlify("D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21")

print(validate_tag(uid, sig))
```

## Contact
Feel free to reach me at ml@icedev.pl if you have any questions concerning this topic.
