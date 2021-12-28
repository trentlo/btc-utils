
from crypto.key import PublicKey

if __name__ == '__main__':

  prvk = PublicKey.gen_random_key()
  print('secret key:')
  print(hex(prvk))

  pubk = PublicKey.from_private_key(prvk)
  print('public key:')
  print('x:', format(pubk.x, '064x'))
  print('y:', format(pubk.y, '064x'))

  addr = pubk.address(net='test', compressed = True)
  print('bitcoin address:')
  print(addr)

