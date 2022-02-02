from cryptography.hazmat.primitives import hashes, hmac, ciphers
import binascii as ba

def byteswap(buffer: bytes) -> bytes:
    return  buffer[::-1]

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    ctx = hmac.HMAC(key, hashes.SHA256())
    ctx.update(msg)
    return ctx.finalize()

def sha256(msg: bytes) -> bytes:
    ctx = hashes.Hash(hashes.SHA256())
    ctx.update(msg)
    return ctx.finalize()

def aes_ctr(key: bytes, iv: bytes):
    return ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.CTR(iv))

def aes_ctr_dec(key: bytes, iv: bytes, txt: bytes) -> bytes:
    ctx = aes_ctr(key, iv).decryptor()
    return ctx.update(txt) + ctx.finalize()

def aes_ctr_enc(key: bytes, iv: bytes, txt: bytes) -> bytes:
    ctx = aes_ctr(key, iv).encryptor()
    return ctx.update(txt) + ctx.finalize()

def kdf(key: bytes, label: str, output_len: int = 32) -> bytes:
    
    output = b''
    suffix = label.encode('ascii') + b'\0'*5 + (output_len*8).to_bytes(4, 'little')

    for i in range(1, 1 + ((output_len+31) >> 5)):
        output += hmac_sha256(key, i.to_bytes(4, 'big') + suffix)

    return output[:output_len]

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
    #secret = ba.a2b_hex('982f8a4291443771cffbc0b5a5dbb5e95bc25639f111f159a4823f92d55e1cab')
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

if __name__ == "__main__":

    # controls
    wrapping_aes_key_correct = byteswap(ba.a2b_hex('def5ce4e3896777e19e6f09552253bf587bcef53540eb846bc91b69db930c3f7'))

    wrapping_hmac_key_correct = byteswap(ba.a2b_hex('c8dc593867e497dd73b11a4669ed425a377bf7698e33c991a0a0922ff5676f57'))

    signature_hmac_key_correct = byteswap(ba.a2b_hex('66ef0c1cbf1491a01e6249000dff641407ded27341b1ef3fd203b1b06474cadd'))

    ccd7_key_hash_correct = ba.a2b_hex('5c4aad785603dc702da3a87aee8017de255743671a5b5b0c56a7de10747e7cc2')

    aes_ikey_correct = ba.a2b_hex('8c2a4fbd636ea09acaa1b30c58ed8e3be9b84cab9b6c8146a6510eea096ef691')
    aes_key_correct = byteswap(ba.a2b_hex('986b02d27d60f3071aa794343407cc39'))

    hmac_ikey_correct = ba.a2b_hex('1473ffeec807413fc45c9748d9fdee41bb7ebfa86499d31a1a7bd4e492b57623')
    hmac_key_correct = ba.a2b_hex('a82c5d6424ad0a70a2f4334a69385539f63cda66ab96881ba1702aaad385a66f')

    # tests

    keys = get_keys()
    assert keys.wrapping_aes_key == wrapping_aes_key_correct
    assert keys.wrapping_hmac_key == wrapping_hmac_key_correct
    assert keys.signature_hmac_key == signature_hmac_key_correct

    assert keys.ftpm_key_mod_hash == ccd7_key_hash_correct

    assert keys.aes_i_key == aes_ikey_correct
    assert keys.aes_key == aes_key_correct

    assert keys.hmac_i_key == hmac_ikey_correct
    assert keys.hmac_key == hmac_key_correct






