from Crypto.Cipher import AES
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
    ciphertext = shares[0].ciphertext
    nonce = ciphertext[:16]
    tag = ciphertext[16:31]
    ciphertext = ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return None
