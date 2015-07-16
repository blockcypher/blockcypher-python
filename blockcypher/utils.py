import re

from hashlib import sha256

from .constants import (SHA_COINS, SCRYPT_COINS, COIN_SYMBOL_LIST,
    COIN_SYMBOL_MAPPINGS, FIRST4_MKEY_CS_MAPPINGS_UPPER)


SATOSHIS_PER_BTC = 10**8
SATOSHIS_PER_MILLIBITCOIN = 10**5

HEX_CHARS_RE = re.compile('^[0-9a-f]*$')


def btc_to_satoshis(btc):
    return int(float(btc) * SATOSHIS_PER_BTC)


def satoshis_to_btc(satoshis):
    return float(satoshis) / float(SATOSHIS_PER_BTC)


def satoshis_to_btc_rounded(satoshis, decimals=4):
    btc = satoshis_to_btc(satoshis)
    if decimals:
        return round(btc, decimals)
    else:
        return btc


def uses_only_hash_chars(string):
    return HEX_CHARS_RE.match(string)


def is_valid_hash(string):
    string = str(string)  # in case of being passed an int
    return len(string.strip()) == 64 and uses_only_hash_chars(string)


### Blocks ###

def is_valid_block_num(block_num):
    try:
        bn_as_int = int(block_num)
    except:
        return False

    # hackey approximation
    return 0 <= bn_as_int <= 10**8


def is_valid_sha_block_hash(block_hash):
    return is_valid_hash(block_hash) and block_hash[:5] == '00000'


def is_valid_scrypt_block_hash(block_hash):
    " Unfortunately this is indistiguishable from a regular hash "
    return is_valid_hash(block_hash)


def is_valid_sha_block_representation(block_representation):
    return is_valid_block_num(block_representation) or is_valid_sha_block_hash(block_representation)


def is_valid_scrypt_block_representation(block_representation):
    return is_valid_block_num(block_representation) or is_valid_scrypt_block_hash(block_representation)


def is_valid_bcy_block_representation(block_representation):
    block_representation = str(block_representation)
    # TODO: more specific rules
    if is_valid_block_num(block_representation):
        return True
    elif is_valid_hash(block_representation):
        if block_representation[:4] == '0000':
            return True
    return False


def is_valid_block_representation(block_representation, coin_symbol):
    # TODO: make handling of each coin more unique
    assert is_valid_coin_symbol(coin_symbol)

    # defensive checks
    if coin_symbol in SHA_COINS:
        if coin_symbol == 'bcy':
            return is_valid_bcy_block_representation(block_representation)
        else:
            return is_valid_sha_block_representation(block_representation)
    elif coin_symbol in SCRYPT_COINS:
        return is_valid_scrypt_block_representation(block_representation)


### Coin Symbol ###

def is_valid_coin_symbol(coin_symbol):
    return coin_symbol in COIN_SYMBOL_LIST


def coin_symbol_from_mkey(mkey):
    '''
    Take the first four of a master public or private key and return the coin_symbol

    Case insensitive to be forgiving of user error
    '''
    return FIRST4_MKEY_CS_MAPPINGS_UPPER.get(mkey[:4].upper())

### Addresses ###

# Copied 2014-09-24 from http://rosettacode.org/wiki/Bitcoin/address_validation#Python

DIGITS58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


# From https://github.com/nederhoed/python-bitcoinaddress/blob/cb483b875d4467ef798d178e232b357a153bed72/bitcoinaddress/validation.py
def _long_to_bytes(n, length, byteorder):
    """Convert a long to a bytestring
    For use in python version prior to 3.2
    Source:
    http://bugs.python.org/issue16580#msg177208
    """
    if byteorder == 'little':
        indexes = range(length)
    else:
        indexes = reversed(range(length))
    return bytearray((n >> i * 8) & 0xff for i in indexes)


def decode_base58(bc, length):
    n = 0
    for char in bc:
        n = n * 58 + DIGITS58.index(char)
    try:
        return n.to_bytes(length, 'big')
    except AttributeError:
        return _long_to_bytes(n, length, 'big')


def crypto_address_valid(bc):
    bcbytes = decode_base58(bc, 25)
    return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]


def is_valid_address(b58_address):
    try:
        return crypto_address_valid(b58_address)
    except:
        # handle edge cases like an address too long to decode
        return False


def is_valid_address_for_coinsymbol(b58_address, coin_symbol):
    '''
    Is an address both valid *and* start with the correct character
    for its coin symbol (chain/network)
    '''
    assert is_valid_coin_symbol(coin_symbol)

    if b58_address[0] in COIN_SYMBOL_MAPPINGS[coin_symbol]['address_first_char_list']:
        if is_valid_address(b58_address):
            return True
    return False
