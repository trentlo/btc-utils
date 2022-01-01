
import sys
from getopt import getopt
from crypto.key import PublicKey, PrivateKey

if __name__ == '__main__':
  # Always use the compressed form now.
  compressed = True
  net = "main"
  mnemonic = None

  argv = sys.argv[1:]
  try:
    # -n (net)
    # `-d mnemonic`: deterministic key gen using
    opts, args = getopt(argv, "n:d:", ["net=", "deterministic="])
  except:
    print("Error")

  for opt, arg in opts:
    if opt in ['-n', "--net"]:
      net = arg
    elif opt in ['-d', '--deterministic']:
      mnemonic = arg

  if mnemonic == None:
    prvk = PrivateKey.gen_random_key()
  else:
    print('gen secret key using mnemonic: ')
    print(mnemonic)
    prvk = PrivateKey.from_mnemonic(mnemonic)
  print('secret key:')
  print(hex(prvk.key).upper())

  wif_prvk : str = prvk.get_wif(net = net, compressed = compressed)
  print('WIF secret key:')
  print(wif_prvk)

  pubk = PublicKey.from_private_key(prvk.key)
  print('public key:')
  print('x:', format(pubk.x, '064x'))
  print('y:', format(pubk.y, '064x'))

  addr = pubk.address(net = net, compressed = compressed)
  print('bitcoin address:')
  print(addr)

