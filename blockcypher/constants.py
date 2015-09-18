# Ordered List of Coin Symbol Dictionaries
COIN_SYMBOL_ODICT_LIST = [
        {
            'coin_symbol': 'btc',
            'display_name': 'Bitcoin',
            'display_shortname': 'BTC',
            'blockcypher_code': 'btc',
            'blockcypher_network': 'main',
            'currency_abbrev': 'BTC',
            'pow': 'sha',
            'example_address': '16Fg2yjwrbtC6fZp61EV9mNVKmwCzGasw5',
            'address_first_char_list': ('1', '3', '4'),
            'first4_mprv': 'xprv',
            'first4_mpub': 'xpub',
            'vbyte_pubkey': 0,
            'vbyte_script': 5,
            },
        {
            'coin_symbol': 'btc-testnet',
            'display_name': 'Bitcoin Testnet',
            'display_shortname': 'BTC Testnet',
            'blockcypher_code': 'btc',
            'blockcypher_network': 'test3',
            'currency_abbrev': 'BTC',
            'pow': 'sha',
            'example_address': '2N1rjhumXA3ephUQTDMfGhufxGQPZuZUTMk',
            'address_first_char_list': ('m', 'n', '2', 'z'),
            'first4_mprv': 'tprv',
            'first4_mpub': 'tpub',
            'vbyte_pubkey': 111,
            'vbyte_script': 196,
            },
        {
            'coin_symbol': 'ltc',
            'display_name': 'Litecoin',
            'display_shortname': 'LTC',
            'blockcypher_code': 'ltc',
            'blockcypher_network': 'main',
            'currency_abbrev': 'LTC',
            'pow': 'scrypt',
            'example_address': 'LcFFkbRUrr8j7TMi8oXUnfR4GPsgcXDepo',
            'address_first_char_list': ('L', 'U', '3', '4'),
            'first4_mprv': 'Ltpv',
            'first4_mpub': 'Ltub',
            'vbyte_pubkey': 48,
            'vbyte_script': 5,
            },
        {
            'coin_symbol': 'doge',
            'display_name': 'Dogecoin',
            'display_shortname': 'DOGE',
            'blockcypher_code': 'doge',
            'blockcypher_network': 'main',
            'currency_abbrev': 'DOGE',
            'pow': 'scrypt',
            'example_address': 'D7Y55r6Yoc1G8EECxkQ6SuSjTgGJJ7M6yD',
            'address_first_char_list': ('D', '9', 'A', '2'),
            'first4_mprv': 'dgpv',
            'first4_mpub': 'dgub',
            'vbyte_pubkey': 30,
            'vbyte_script': 22,
            },
        {
            'coin_symbol': 'uro',
            'display_name': 'Uro',
            'display_shortname': 'URO',
            'blockcypher_code': 'uro',
            'blockcypher_network': 'main',
            'currency_abbrev': 'URO',
            'pow': 'sha',
            'example_address': 'Uhf1LGdgmWe33hB9VVtubyzq1GduUAtaAJ',
            'address_first_char_list': ('U', ),  # TODO: more?
            },
        {
            'coin_symbol': 'bcy',
            'display_name': 'BlockCypher Testnet',
            'display_shortname': 'BCY Testnet',
            'blockcypher_code': 'bcy',
            'blockcypher_network': 'test',
            'currency_abbrev': 'BCY',
            'pow': 'sha',
            'example_address': 'CFr99841LyMkyX5ZTGepY58rjXJhyNGXHf',
            'address_first_char_list': ('B', 'C', 'D', 'Y'),
            'first4_mprv': 'bprv',
            'first4_mpub': 'bpub',
            'vbyte_pubkey': 27,
            'vbyte_script': 31,
            },
        ]

# all fields required
REQUIRED_FIELDS = (
    'coin_symbol',  # this is a made up unique symbole for library use only
    'display_name',  # what it commonly looks like
    'display_shortname',  # an abbreviated version of display_name (for when space is tight)
    'blockcypher_code',  # blockcypher's unique ID (for their URLs)
    'blockcypher_network',  # the blockcypher network (main/test)
    'currency_abbrev',  # what the unit of currency looks like when abbreviated
    'pow',  # the proof of work algorithm (sha/scrypt)
    'example_address',  # an example address
    )

ELIGIBLE_POW_ENTRIES = set(['sha', 'scrypt'])

# Safety checks on the data
for coin_symbol_dict in COIN_SYMBOL_ODICT_LIST:
    # Make sure POW is set correctly
    assert coin_symbol_dict['pow'] in ELIGIBLE_POW_ENTRIES, coin_symbol_dict['pow']
    # Make sure no fields are missing
    for required_field in REQUIRED_FIELDS:
        assert required_field in coin_symbol_dict


COIN_SYMBOL_LIST = [x['coin_symbol'] for x in COIN_SYMBOL_ODICT_LIST]
SHA_COINS = [x['coin_symbol'] for x in COIN_SYMBOL_ODICT_LIST if x['pow'] == 'sha']
SCRYPT_COINS = [x['coin_symbol'] for x in COIN_SYMBOL_ODICT_LIST if x['pow'] == 'scrypt']

# For django-style lists (with "best" order)
COIN_CHOICES = []
for coin_symbol_dict in COIN_SYMBOL_ODICT_LIST:
    COIN_CHOICES.append((coin_symbol_dict['coin_symbol'], coin_symbol_dict['display_name']))

# upper-case to be forgiving on user error
FIRST4_MKEY_CS_MAPPINGS_UPPER = {}
for coin_symbol_dict in COIN_SYMBOL_ODICT_LIST:
    if 'first4_mprv' in coin_symbol_dict:
        FIRST4_MKEY_CS_MAPPINGS_UPPER[coin_symbol_dict['first4_mprv'].upper()] = coin_symbol_dict['coin_symbol']
    if 'first4_mpub' in coin_symbol_dict:
        FIRST4_MKEY_CS_MAPPINGS_UPPER[coin_symbol_dict['first4_mpub'].upper()] = coin_symbol_dict['coin_symbol']

# mappings (similar to above but easier retrieval for when order doens't matter)
# must come last because of popping out
COIN_SYMBOL_MAPPINGS = {}
for coin_symbol_dict in COIN_SYMBOL_ODICT_LIST:
    coin_symbol = coin_symbol_dict.pop('coin_symbol')
    COIN_SYMBOL_MAPPINGS[coin_symbol] = coin_symbol_dict


UNIT_CHOICE_ODICT_LIST = [
        {
            'unit': 'btc',
            'display_name': 'BTC',
            'satoshis_per': 10**8,
            },
        {
            'unit': 'mbtc',
            'display_name': 'mBTC',
            'satoshis_per': 10**5,
            },
        {
            'unit': 'bit',
            'display_name': 'bit',
            'satoshis_per': 10**2,
            },
        {
            'display_name': 'satoshi',
            'unit': 'satoshi',
            },
        ]

UNIT_CHOICES = []
UNIT_CHOICES_DJANGO = []
for unit_choice_dict in UNIT_CHOICE_ODICT_LIST:
    UNIT_CHOICES.append(unit_choice_dict['unit'])
    UNIT_CHOICES_DJANGO.append((unit_choice_dict['unit'], unit_choice_dict['display_name']))

# mappings (similar to above but easier retrieval for when order doens't matter)
# must come last because of popping out
UNIT_MAPPINGS = {}
for unit_choice_dict in UNIT_CHOICE_ODICT_LIST:
    unit_choice = unit_choice_dict.pop('unit')
    UNIT_MAPPINGS[unit_choice] = unit_choice_dict
