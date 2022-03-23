from typing import TypeVar

from cryptography.hazmat.primitives import hashes, hmac, ciphers
from psptool import PSPTool

import binascii as ba

T = TypeVar('T')


def sole(set_of_one: set[T], assert_msg="Set does not contain exactly one element") -> T:
    assert len(set_of_one) == 1, assert_msg
    return list(set_of_one)[0]


def byteswap(buffer: bytes) -> bytes:
    return buffer[::-1]


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
    suffix = label.encode('ascii') + b'\0' * 5 + (output_len * 8).to_bytes(4, 'little')

    for i in range(1, 1 + ((output_len + 31) >> 5)):
        output += hmac_sha256(key, i.to_bytes(4, 'big') + suffix)

    return output[:output_len]


class SecretKeys:
    def __init__(self, secret: bytes):
        self.secret = secret
        self.wrapping_aes_key = kdf(secret, 'AES Key for wrapping data')
        self.wrapping_hmac_key = kdf(secret, 'HMAC Key for wrapping data')
        self.signature_hmac_key = kdf(secret, 'HMAC Signature Key for PSP Data saved in DRAM')


def unseal_secret(sealed_secret: bytes, lsb_key: bytes):
    ctx = ciphers.Cipher(ciphers.algorithms.AES(lsb_key), ciphers.modes.ECB()).encryptor()
    return ctx.update(sealed_secret) + ctx.finalize()


class NvDataKeys(SecretKeys):
    @staticmethod
    def from_file_and_hex(filename: str, lsb_key_hex: str):
        pt = PSPTool.from_file(filename)

        # For all portions of the NvDataKeys let's fetch all possible inputs and assert they are the same using sole()
        driver_entries = pt.blob.get_entries_by_type(0x28)
        psp_boot_time_trustlets = pt.blob.get_entries_by_type(0xc)

        # 1. sealed_secret:
        sealed_secrets = set()
        for de in driver_entries:
            # We suspect the sealed_secret right before this string
            sealed_secret_size = 0x20
            offset = de.get_bytes().find(b"HMAC Signature Key for PSP Data saved in DRAM") - sealed_secret_size
            sealed_secrets.add(
                de.get_bytes(offset, sealed_secret_size)
            )
        sealed_secret = sole(sealed_secrets)
        lsb_key = ba.unhexlify(lsb_key_hex)
        secret = unseal_secret(sealed_secret, lsb_key)

        # 2. ftpm_key_modulus
        ftpm_key_moduli = set()
        for pbtt in psp_boot_time_trustlets:
            assert len(pbtt.signed_entity.certifying_keys) == 1
            ck = list(pbtt.signed_entity.certifying_keys)[0]
            pk = ck.get_public_key()
            ftpm_key_moduli.add(
                pk.get_crypto_material(pk.signature_size)
            )
        ftpm_key_modulus: bytes = sole(ftpm_key_moduli)

        # 3. ftpm_app_id
        ftpm_app_ids = set()
        for pbtt in psp_boot_time_trustlets:
            magic = b"gpd.ta.appID"
            offset = pbtt.get_bytes().find(magic) + len(magic) + 1
            ftpm_app_ids.add(
                pbtt.get_bytes(offset, 0x10)
            )
        ftpm_app_id = sole(ftpm_app_ids)

        return NvDataKeys(secret, ftpm_key_modulus, ftpm_app_id)

    def __init__(self, secret: bytes, ftpm_key_modulus: bytes, ftpm_app_id: bytes):
        super().__init__(secret)
        self.ftpm_key_modulus = ftpm_key_modulus
        self.ftpm_key_mod_hash = sha256(ftpm_key_modulus)
        self.ftpm_app_id = ftpm_app_id

        self.aes_i_key = hmac_sha256(self.wrapping_aes_key, self.ftpm_key_mod_hash)
        self.hmac_i_key = hmac_sha256(self.wrapping_hmac_key, self.ftpm_key_mod_hash)

        self.aes_key = hmac_sha256(self.aes_i_key, self.ftpm_app_id)[:16]
        self.hmac_key = hmac_sha256(self.hmac_i_key, self.ftpm_app_id)


if __name__ == "__main__":
    # controls
    wrapping_aes_key_correct = byteswap(ba.a2b_hex('def5ce4e3896777e19e6f09552253bf587bcef53540eb846bc91b69db930c3f7'))

    wrapping_hmac_key_correct = byteswap(ba.a2b_hex('c8dc593867e497dd73b11a4669ed425a377bf7698e33c991a0a0922ff5676f57'))

    signature_hmac_key_correct = byteswap(
        ba.a2b_hex('66ef0c1cbf1491a01e6249000dff641407ded27341b1ef3fd203b1b06474cadd'))

    ccd7_key_hash_correct = ba.a2b_hex('5c4aad785603dc702da3a87aee8017de255743671a5b5b0c56a7de10747e7cc2')

    aes_ikey_correct = ba.a2b_hex('8c2a4fbd636ea09acaa1b30c58ed8e3be9b84cab9b6c8146a6510eea096ef691')
    aes_key_correct = byteswap(ba.a2b_hex('986b02d27d60f3071aa794343407cc39'))

    hmac_ikey_correct = ba.a2b_hex('1473ffeec807413fc45c9748d9fdee41bb7ebfa86499d31a1a7bd4e492b57623')
    hmac_key_correct = ba.a2b_hex('a82c5d6424ad0a70a2f4334a69385539f63cda66ab96881ba1702aaad385a66f')

    # tests

    keys = NvDataKeys.from_file_and_hex(
        '/Users/cwerling/Git/psp-emulation/asrock/roms/ASRock_A520M_HVS_1.31.ftpm_with_data',
        'fb2aaa2268624d6b0cfb1f8b69f936e84377b0f8169668dc0453484a33f81544'
    )
    assert keys.wrapping_aes_key == wrapping_aes_key_correct
    assert keys.wrapping_hmac_key == wrapping_hmac_key_correct
    assert keys.signature_hmac_key == signature_hmac_key_correct

    assert keys.ftpm_key_mod_hash == ccd7_key_hash_correct

    assert keys.aes_i_key == aes_ikey_correct
    assert keys.aes_key == aes_key_correct

    assert keys.hmac_i_key == hmac_ikey_correct
    assert keys.hmac_key == hmac_key_correct
