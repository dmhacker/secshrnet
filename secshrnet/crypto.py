from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Hash import BLAKE2s
from collections import Counter

from . import network_pb2


class ShareError(Exception):
    pass


def encrypt_plaintext(message, password):
    '''
    :param bytes message: Plaintext message
    :param bytes password: Password bytes
    :return: Ciphertext result
    :rtype: bytes
    '''
    salt = get_random_bytes(32)
    key = scrypt(password, salt, 32, N=2**20, r=8, p=1)
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(message)
    # 12 bytes is the default nonce length
    assert(len(cipher.nonce) == 12)
    assert(len(tag) == 16)
    return salt + cipher.nonce + tag + ct


def decrypt_ciphertext(ct, password):
    '''
    :param bytes ct: Ciphertext message
    :param bytes password: Password bytes
    :return: Plaintext result
    :rtype: bytes
    '''
    salt = ct[:32]
    nonce = ct[32:44]
    tag = ct[44:60]
    ct = ct[60:]
    key = scrypt(password, salt, 32, N=2**20, r=8, p=1)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None


def split_shares(message, threshold, share_count):
    '''
    :param bytes message: Message bytes
    :param int threshold: Minimum number of shares needed for reconstruction
    :param int share_count: Number of shares to produce
    :return: List of protobuf shares
    :rtype: [network_pb2.Share]
    '''
    if threshold > share_count:
        raise ShareError("Threshold must not be greater than the share count.")
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(message)
    # Tag and nonce should both be 16 bytes
    assert(len(cipher.nonce) == 16)
    assert(len(tag) == 16)
    full_ct = cipher.nonce + tag + ct
    raw_shares = Shamir.split(threshold, share_count, key)

    def _to_protobuf(raw_share):
        share = network_pb2.Share()
        share.index = raw_share[0]
        share.key_share = raw_share[1]
        share.ciphertext = full_ct
        hasher = BLAKE2s.new(digest_bits=256)
        hasher.update(message)
        share.ciphertext_hash = hasher.digest()
        return share

    return list(map(_to_protobuf, raw_shares))


def combine_shares(shares):
    '''
    :param [network_pb2.Share] message: List of protobuf shares
    :return: Reconstructed message if possible
    :rtype: bytes
    '''
    if not shares:
        raise ShareError("No shares for the given tag.")
    hashes = [share.ciphertext_hash for share in shares]
    max_hash, _ = Counter(hashes).most_common(1)[0]
    majority_shares = [share for share in shares if
                       share.ciphertext_hash == max_hash]

    def _to_raw(share):
        return (share.index, share.key_share)

    key = Shamir.combine(list(map(_to_raw, majority_shares)))
    ct = majority_shares[0].ciphertext
    nonce = ct[:16]
    tag = ct[16:32]
    ct = ct[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        raise ShareError("Not enough shares acquired to produce "
                         "a valid message.")
