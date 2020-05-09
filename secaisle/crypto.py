from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Hash import BLAKE2s

import comms_pb2
import base64


def encrypt_plaintext(message, key):
    '''
    :param bytes message: Plaintext message
    :param bytes key: 32-byte symmetric key
    :return: Ciphertext result
    :rtype: bytes
    '''
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(message)
    # 12 bytes is the default nonce length
    assert(len(cipher.nonce) == 12)
    assert(len(tag) == 16)
    return cipher.nonce + tag + ct


def decrypt_ciphertext(ct, key):
    '''
    :param bytes ct: Ciphertext message
    :param bytes key: 32-byte symmetric key
    :return: Plaintext result
    :rtype: bytes
    '''
    nonce = ct[:12]
    tag = ct[12:28]
    ct = ct[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None


def hash256(message, hex_output=False):
    '''
    :param bytes message: Message bytes
    :param bool hex_output: If true, output is a hexadecimal string.
    :return: Digest of the message
    :rtype: str if hex_output else bytes
    '''
    hasher = BLAKE2s.new(digest_bits=256)
    hasher.update(message)
    return hasher.hexdigest() if hex_output else hasher.digest()


def split_shares(message, threshold, share_count):
    '''
    :param bytes message: Message bytes
    :param int threshold: Minimum number of shares needed for reconstruction
    :param int share_count: Number of shares to produce
    :return: A list of protobuf shares objects
    :rtype: [comms_pb2.Share]
    '''
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(message)
    # Tag and nonce should both be 16 bytes
    assert(len(cipher.nonce) == 16)
    assert(len(tag) == 16)
    full_ct = cipher.nonce + tag + ct
    raw_shares = Shamir.split(threshold, share_count, key)

    def _to_protobuf(raw_share):
        share = comms_pb2.Share()
        share.index = raw_share[0]
        share.key_share = base64.b64encode(raw_share[1]).decode()
        share.ciphertext = base64.b64encode(full_ct).decode()
        share.ciphertext_hash = hash256(full_ct, hex_output=True)
        return share

    return list(map(_to_protobuf, raw_shares))


def combine_shares(shares):
    if not shares:
        return None

    def _to_raw(share):
        key_share = base64.b64decode(share.key_share.encode())
        return (share.index, key_share)

    key = Shamir.combine_shares(list(map(_to_raw, shares)))
    ct = base64.b64decode(shares[0].ciphertext.encode())
    nonce = ct[:16]
    tag = ct[16:31]
    ct = ct[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag).decode()
    except ValueError:
        return None
