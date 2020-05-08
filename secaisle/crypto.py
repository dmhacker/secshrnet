from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.secret_sharing import Shamir

import packets_pb2


def split_shares(content, threshold, share_count):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest()
    # Tag and nonce should both be 16 bytes
    assert(len(cipher.nonce) == 16)
    assert(len(ct) == 16)
    raw_shares = Shamir.split(threshold, share_count, key)

    def _to_protobuf(raw_share):
        share = packets_pb2.Share()
        share.id = raw_share[0]
        share.key_share = raw_share[1]
        share.ciphertext = cipher.nonce + tag + ct
        return share

    return raw_shares.map(_to_protobuf)


def combine_shares(shares):
    if not shares:
        return None

    def _to_raw(share):
        return (share.id, share.key_share)

    key = Shamir.combine_shares(shares.map(_to_raw))
    ct = shares[0].ciphertext
    nonce = ct[:16]
    tag = ct[16:31]
    ct = ct[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None


def encrypt_plaintext(content, key):
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(content)
    assert(len(cipher.nonce) == 12)
    assert(len(tag) == 16)
    return cipher.nonce + tag + ct


def decrypt_ciphertext(content, key):
    nonce = content[:12]
    tag = content[12:28]
    ct = content[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        return None
