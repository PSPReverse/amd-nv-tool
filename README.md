# amdnvtool

This tool can parse and decrypt the `NV_DATA` entry.

## Prerequisites

Installing the package in a python venv:
```bash
$ python3.8 -m venv venv
$ . venv/bin/activate
$ pip install -U pip setuptools_rust
$ pip install -e .
```

## Example

Decoding the example nvdata blob:
```bash
$ amdnvtool example.nvdata
Context 4
  [x'84090000', x'fac9aeb5dd2f95b771e75aa7']
  [x'90090000', x'7451d3a7d7f24213d0027f5f']
  [x'e8110000', x'c404bf82d17be872b5a4dc69']
Context 5
  [x'01000000', x'72c649a968d81894c0332cdc']
...
```

This example `NV_DATA` blob has been taken from our Ryzen 3600 CPU in an Asrock A520M-HDV motherboard.
The decryption keys are derived from a hardcoded secret in the `amdnvtool/crypto.py` file:
```python
class SecretKeys:
    def __init__(self, secret: bytes):
        self.secret = secret
        self.wrapping_aes_key = kdf(secret, 'AES Key for wrapping data')
        self.wrapping_hmac_key = kdf(secret, 'HMAC Key for wrapping data')
        self.signature_hmac_key = kdf(secret, 'HMAC Signature Key for PSP Data saved in DRAM')

class NvDataKeys(SecretKeys):
    def __init__(self, secret, ftpm_key_modulus, ftpm_app_id):
        super().__init__(secret)
        self.ftpm_key_modulus = ftpm_key_modulus
        self.ftpm_key_mod_hash = sha256(ftpm_key_modulus)
        self.ftpm_app_id = ftpm_app_id

        self.aes_i_key = hmac_sha256(self.wrapping_aes_key, self.ftpm_key_mod_hash)
        self.hmac_i_key = hmac_sha256(self.wrapping_hmac_key, self.ftpm_key_mod_hash)

        self.aes_key = hmac_sha256(self.aes_i_key, self.ftpm_app_id)[:16]
        self.hmac_key = hmac_sha256(self.hmac_i_key, self.ftpm_app_id)

def get_keys():

    # inputs
    secret = ba.a2b_hex('89c209ab1571b23c84b9fef0a1416fbc9482b014cc5fe242a797b72df028556f')

    ftpm_app_id = ba.a2b_hex('00b5a2ab4538ca45bb56f2e5ae71c585')

    ccd7_key_modulus = ba.a2b_hex(
        'e9451471a33663ade48d5d8a4fe587f9'
        + 'c6687c89c83a3b8c6d892e610cf5032c'
        + '2d9377d5c5639eb820cf1ca5d39aedcb'
        + 'aaa3b8313412ecc84699581808090b60'
        + '68333d318f56d0271e13696c7ec0d4fe'
        + '902e7832125ff1004961a900581c6189'
        + '5ac8a52ef05278777ffaec5df49ce88c'
        + '7b6bcec897a9ef780d512cd2b490fb55'
        + '9cef174e98ad83bb2ad755af371df768'
        + '6e058977268d6dbd0f1fbe24d48d057a'
        + '9649202ef73eb02005edaa72d267cb99'
        + '6a26416e37a70225ddb22593dc7fcb2a'
        + '397ae843cb41ec3f7eaebe32fda6fddc'
        + 'cf455ca5134b192ef5e03a8ca63b8b66'
        + '8a9c87e213654691f5be6ea27f89eae0'
        + 'c2871f6c66efc46b979700e1488c39e6'
    )

    return NvDataKeys(secret, ccd7_key_modulus, ftpm_app_id)

```
