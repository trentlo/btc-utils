#
# Taken from https://github.com/karpathy/cryptos
#

# -----------------------------------------------------------------------------
# base58 encoding / decoding utilities
# reference: https://en.bitcoin.it/wiki/Base58Check_encoding

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
alphabet_inv = {c:i for i,c in enumerate(alphabet)}

def b58encode(b: bytes) -> str:
    assert len(b) == 25 # version is 1 byte, pkb_hash 20 bytes, checksum 4 bytes
    n = int.from_bytes(b, 'big')
    chars = []
    while n:
        n, i = divmod(n, 58)
        chars.append(alphabet[i])
    # special case handle the leading 0 bytes... ¯\_(ツ)_/¯
    num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    res = num_leading_zeros * alphabet[0] + ''.join(reversed(chars))
    return res

def b58decode(res: str) -> bytes:
    n = sum(alphabet_inv[c] * 58**i for i, c in enumerate(reversed(res)))
    return n.to_bytes(25, 'big') # version, pkb_hash, checksum bytes

def address_to_pkb_hash(b58check_address: str) -> bytes:
    """ given an address in b58check recover the public key hash """
    byte_address = b58decode(b58check_address)
    # validate the checksum
    assert byte_address[-4:] == sha256(sha256(byte_address[:-4]))[:4]
    # strip the version in front and the checksum at tail
    pkb_hash = byte_address[1:-4]
    return pkb_hash
