
from crypto.key import PublicKey, PrivateKey

if __name__ == '__main__':

  prvk = PrivateKey.gen_random_key()
  print('secret key:')
  print(hex(prvk.key).upper())

  wip_prvk : str = prvk.get_wip(net='main', compressed = True)
  print('wip secret key:')
  print(wip_prvk)

  pubk = PublicKey.from_private_key(prvk.key)
  print('public key:')
  print('x:', format(pubk.x, '064x'))
  print('y:', format(pubk.y, '064x'))

  addr = pubk.address(net='main', compressed = True)
  print('bitcoin address:')
  print(addr)

