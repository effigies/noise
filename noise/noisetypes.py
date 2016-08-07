from collections import namedtuple
from .error import HashError

from pysodium import \
    crypto_aead_chacha20poly1305_encrypt as chachapoly_encrypt, \
    crypto_aead_chacha20poly1305_decrypt as chachapoly_decrypt
import libnacl
from libnacl import \
    crypto_box_keypair as x25519_keypair, \
    crypto_box_beforenm as x25519_dh, \
    crypto_hash_sha256 as sha256_hash, \
    crypto_hash_sha512 as sha512_hash, \
    crypto_generichash as blake2b_hash

# Set BLAKE2b HASHLEN
libnacl.crypto_generichash_BYTES = 64


class Singleton(object):
    """Object type that produces exactly one instance"""
    _instance = None

    def __new__(klass, *args, **kwargs):
        """Return instance of class, creating if necessary"""
        if klass._instance is None:
            klass._instance = object.__new__(klass, *args, **kwargs)
        return klass._instance


class Empty(Singleton):
    """Special empty value

    Use ``empty'' instantiation"""

empty = Empty()


KeyPair = namedtuple('KeyPair', ('public_key', 'private_key'))


class DH(Singleton):
    DHLEN = None
    NAME = b''

    @classmethod
    def generate_keypair(klass):
        raise NotImplementedError

    @classmethod
    def DH(klass, keypair, public_key):
        raise NotImplementedError


class X25519(DH):
    DHLEN = 32
    NAME = b'25519'

    @classmethod
    def generate_keypair(klass):
        return KeyPair(*x25519_keypair())

    @classmethod
    def DH(klass, keypair, public_key):
        return x25519_dh(public_key, keypair.private_key)


class X448(DH):
    DHLEN = 56
    NAME = b'448'


class Cipher(Singleton):
    @classmethod
    def encrypt(klass, k, n, ad, plaintext):
        raise NotImplementedError

    @classmethod
    def decrypt(klass, k, n, ad, ciphertext):
        raise NotImplementedError


class ChaChaPoly(Cipher):
    NAME = b'ChaChaPoly'

    @classmethod
    def encrypt(klass, k, n, ad, plaintext):
        return chachapoly_encrypt(plaintext, ad, n, k)

    @classmethod
    def decrypt(klass, k, n, ad, ciphertext):
        return chachapoly_decrypt(ciphertext, ad, n, k)


class AESGCM(Cipher):
    NAME = b'AESGCM'


class Hash(Singleton):
    HASHLEN = None
    BLOCKLEN = None

    @classmethod
    def hash(klass, inputbytes):
        raise NotImplementedError

    @classmethod
    def hmac_hash(klass, key, data):
        if len(key) < klass.BLOCKLEN:
            key = key.rjust(klass.BLOCKLEN, b'\x00')
        else:
            key = klass.hash(key)

        opad = bytes(0x5c ^ byte for byte in key)
        ipad = bytes(0x36 ^ byte for byte in key)
        return klass.hash(opad + klass.hash(ipad + data))

    @classmethod
    def hkdf(klass, chaining_key, input_key_material, dh=X25519):
        """Hash-based key derivation function

        dh parameter should be set to the Diffie-Hellman class

        Takes a ``chaining_key'' byte sequence of len HASHLEN, and an
        ``input_key_material'' byte sequence with length either zero
        bytes, 32 bytes or DHLEN bytes.

        Returns two byte sequences of length HASHLEN"""
        if len(chaining_key) != klass.HASHLEN:
            raise HashError("Incorrect chaining key length")
        if len(input_key_material) not in (0, 32, dh.DHLEN):
            raise HashError("Incorrect input key material length")
        temp_key = klass.hmac_hash(chaining_key, input_key_material)
        output1 = klass.hmac_hash(temp_key, b'\x01')
        output2 = klass.hmac_hash(temp_key, output1 + b'\x02')
        return output1, output2


class SHA256(Hash):
    HASHLEN = 32
    BLOCKLEN = 64
    NAME = b'SHA256'
    hash = sha256_hash


class SHA512(Hash):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b'SHA512'
    hash = sha512_hash


class BLAKE2s(Hash):
    HASHLEN = 32
    BLOCKLEN = 64
    NAME = b'BLAKE2s'


class BLAKE2b(Hash):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b'BLAKE2b'
    hash = blake2b_hash


class NoiseBuffer(object):
    """Pre-allocated bytestring buffer with append interface

    Strict mode prevents increasing beyond the original buffer size,
    while non-strict mode permits arbitrary appends.

    When done appending, retrieve final values with bytes(...)
    """
    def __init__(self, nbytes=0, strict=False):
        self.bfr = bytearray(nbytes)
        self.length = 0
        self.strict = strict

    def __len__(self):
        return self.length

    def append(self, val):
        """Append byte string val to buffer

        If the result exceeds the length of the buffer, behavior
        depends on whether instance was initialized as strict.

        In strict mode, a ValueError is raised.
        In non-strict mode, the buffer is extended as necessary.
        """
        new_len = self.length + len(val)
        to_add = new_len - len(self.bfr)
        if self.strict and to_add > 0:
            raise ValueError("Cannot resize buffer")
        self.bfr[self.length:new_len] = val
        self.length = new_len

    def __bytes__(self):
        """Return immutable copy of buffer

        In strict mode, return entire pre-allocated buffer, initialized
        to 0x00 where not overwritten.

        In non-strict mode, return only written bytes.
        """
        if self.strict:
            return bytes(self.bfr)
        else:
            return bytes(self.bfr[:self.length])
