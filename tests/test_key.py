#
# Ported from https://github.com/karpathy/cryptos
#

"""
Test the generation of secret/public keypairs and bitcoin addreses
"""

from crypto.key import PublicKey, PrivateKey
from crypto.b58check import b58decode
from crypto.sha256 import sha256

def test_public_key_gen():

    # Example taken from Chapter 4 of Mastering Bitcoin
    # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    public_key = PublicKey.from_private_key('1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD')
    assert format(public_key.x, '064x').upper() == 'F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A'
    assert format(public_key.y, '064x').upper() == '07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB'


def test_btc_addresses():

    # tuples of (net, compressed, secret key in hex, expected compressed bitcoin address string in b58check)
    tests = [
        # Mastering Bitcoin Chapter 4 example
        # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
        ('main', True, '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6', '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'),
        # Bitcoin wiki page reference
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
        ('main', True, '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725', '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'),
        # Programming Bitcoin Chapter 4 Exercise 5
        ('main', True, 0x12345deadbeef, '1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1'),
        ('test', True, 2020**5, 'mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH'),
        ('test', False, 5002, 'mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA'),
    ]

    # test address encoding into b58check
    for net, compressed, secret_key, expected_address in tests:
        pk = PublicKey.from_private_key(secret_key)
        addr = pk.address(net, compressed)
        assert addr == expected_address

    # test public key hash decoding from b58check
    for net, compressed, secret_key, address in tests:
        pk = PublicKey.from_private_key(secret_key)
        # get the hash160 by stripping version byte and checksum
        pkb_hash = pk.encode(compressed)
        # now extract from the address, address_to_pkb_hash

    def address_to_pkb_hash(b58check_address: str) -> bytes:
        """ given an address in b58check recover the public key hash """
        byte_address = b58decode(b58check_address)
        # validate the checksum
        assert byte_address[-4:] == sha256(sha256(byte_address[:-4]))[:4]
        # strip the version in front and the checksum at tail
        pkb_hash = byte_address[1:-4]
        return pkb_hash

    pkb_hash2 = address_to_pkb_hash(address)
    assert pkb_hash == pkb_hash2


def test_wip_private_key():

    # tuples of (net, compressed, secret key in hex, wif secret key, address)
    tests = [
        # testcases generated by feeding generated WIF private keys into Electrum and getting
        # back the BTC addresses.
        ('main', True, 'BEE87275B8F694A2F285CD8F3EC51AD7410E841D8498561D9234D63C89AB991C',
         'L3cozj3fPuMaBebjU173fNQu3UsTiAj4xiyqkjbNAPtS5VY4zvdB', '1KxtHemdM2RNDQYQQQeFr6vt5jd4LooL8E'),
        ('main', True, 'DA1EDDCB20EDFA5B9A7D92875B5A7EA38ABA8AA1B4DD983369F1E48BD6AC5553',
         'L4Xi4ZD4A95BmmXMdhTWzpgpHtoPqwxq1icVxdtqDrWaixbGk5TT', '13YWPv4AAhNwE2MLxrUjbBb8A9W1F4c5QW'),
        ('main', True, '2FE0A07BCA223428F78053B3BDD1A15A9C1DF4625371FA62507701A65CED8BE1',
         'Kxpn6jyrjNjtrp5mZPR1Poho3miAR7s8DzdTT4gD3c7Puxf7LqLe', '17Da5hUS1JcZY88Qif2VwtCXDqfQKtHCZx'),
        ('main', False, '636046F0B855009FFF0BE3DCF247B7A18239BD05F7DE0D03148479C0CB8E9A0D',
         '5Ja41YRns1CL1U3ucfQ5oFMiUfQbE1pSS1VD5KYcTZwTCcB9rBx', '1Jii1TCVHWkjG2KyaXEvaRqrPUmdcpGHKQ'),
    ]

    # test address encoding into b58check
    for net, compressed, secret_key, expected_wif, expected_address in tests:
        prvk = PrivateKey.from_private_key(secret_key)
        wif = prvk.get_wif(net, compressed)
        assert wif == expected_wif
        pubk = PublicKey.from_private_key(prvk.key)
        addr = pubk.address(net, compressed)
        assert addr == expected_address


#TODO: support decode()
#def test_pk_sec():
#
#    G = BITCOIN.gen.G
#
#    # these examples are taken from Programming Bitcoin Chapter 4 exercises
#    tests = [
#        (5000 * G, False, '04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10'),
#        ((2018**5) * G, False, '04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06'),
#        (0xdeadbeef12345 * G, False, '04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121'),
#        (5001 * G, True, '0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1'),
#        ((2019**5) * G, True, '02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701'),
#        (0xdeadbeef54321 * G, True, '0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690'),
#    ]
#
#    for P, compressed, sec_gt in tests:
#        # encode
#        sec = PublicKey.from_point(P).encode(compressed=compressed).hex()
#        assert sec == sec_gt
#        # decode
#        P2 = PublicKey.decode(bytes.fromhex(sec))
#        assert P.x == P2.x and P.y == P2.y
