class NoiseException(Exception):
    """Exceptions related to the Noise Protocol Framework"""


class HandshakeError(NoiseException):
    """Error establishing connection"""


class DecryptError(NoiseException):
    """Error decrypting data"""


class AuthenticationError(NoiseException):
    """Error authenticating payload"""


class HashError(NoiseException):
    """Error while hashing"""


class NonceError(NoiseException):
    """Invalid nonce value"""
