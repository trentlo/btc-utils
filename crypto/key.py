
from __future__ import annotations # PEP 563: Postponed Evaluation of Annotations

import os

from dataclasses import dataclass
from .curve import Curve, Point
from .sha256 import sha256
from .ripemd160 import ripemd160
from .b58check import b58encode

# By default, use secp256k1: http://www.oid-info.com/get/1.3.132.0.10
def get_generator() -> Point:
  p : int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  a : int = 0x0000000000000000000000000000000000000000000000000000000000000000
  b : int = 0x0000000000000000000000000000000000000000000000000000000000000007
  g_x : int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  g_y : int = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  n : int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  curve = Curve(a, b, p, n)
  g = Point(g_x, g_y, curve)
  return g


@dataclass
class PrivateKey():
  """ private keys """
  key : int

  @classmethod
  def from_private_key(cls, prvk) -> PrivateKey:
    """ prvk can be an int or a hex string """
    assert isinstance(prvk, (int, str))
    prvk = int(prvk, 16) if isinstance(prvk, str) else prvk
    return PrivateKey(prvk)

  # n is the order of the subgroup
  @classmethod
  def gen_random_key(cls) -> PrivateKey:
    n = get_generator().curve.n
    while True:
      key = int.from_bytes(os.urandom(32), 'big')
      if 1 <= key < n:
        break;
    return PrivateKey(key)

  @classmethod
  def from_mnemonic(cls, mnemonic : str, num_hash : int) -> PrivateKey:
    temp = bytearray(mnemonic, 'UTF-8')
    #print("before reverse: ", temp)
    temp.reverse() # use little endian
    temp : bytes = temp
    #print("after reverse: ", temp.hex())
    for i in range(num_hash):
      temp = sha256(temp)
      #print(i, ": ", temp)
    key = int.from_bytes(temp, 'big')
    assert get_generator().curve.n // 1024 < key < get_generator().curve.n
    print('ratio = ', key / get_generator().curve.n)
    return PrivateKey(key)

  def get_wif(self, net: str, compressed : bool) -> str:
    """
    Get the private key in Wallet Import Format (WIF).
    https://gist.github.com/t4sk/ac6f2d607c96156ca15f577290716fcc
    """
    k = self.key.to_bytes(32, 'big')
    if compressed:
      k += b'\x01'
    #print(k)
    version = {'main' : b'\x80', 'test' : b'\xef'}
    checksum = sha256(sha256(version[net] + k))[:4]
    ver_privk_checksum = version[net] + k + checksum
    wif = b58encode(ver_privk_checksum)
    return wif

@dataclass
class PublicKey(Point):
  """ public keys """

  @classmethod
  def from_private_key(cls, prvk) -> PublicKey:
    """ prvk can be an int or a hex string """
    assert isinstance(prvk, (int, str))
    prvk = int(prvk, 16) if isinstance(prvk, str) else prvk
    pubk = prvk * get_generator()
    return cls.from_point(pubk)

  @classmethod
  def from_point(cls, pt: Point) -> PublicKey:
    return cls(x = pt.x, y = pt.y, curve = pt.curve)

  def address(self, net: str, compressed: bool) -> str:
    pubk_hash = self.encode(compressed = compressed)
    version = {'main' : b'\x00', 'test' : b'\x6f'}
    ver_pubk_hash = version[net] + pubk_hash
    checksum = sha256(sha256(ver_pubk_hash))[:4]
    byte_address = ver_pubk_hash + checksum
    b58check_address = b58encode(byte_address)
    return b58check_address

  def encode(self, compressed : bool):
    if compressed:
      prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
      pubk = prefix + self.x.to_bytes(32, 'big')
    else:
      pubk = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
    return ripemd160(sha256(pubk))


