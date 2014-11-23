pyblockcypher
=============

Python library for the BlockCypher web services

Currently in beta, more features and support for more endpoints coming soon.

Issues and pull requests much appreciated!

Handles datetime conversions. Designed to be used without having to RTFM.

*Should* support python 2.6+ and python3.x, but hasn't been thoroughly tested. Please file an issue if something isn't working.

#### Installation

Use pip with
```
$ pip3 install -e git+git://github.com/blockcypher/pyblockcypher.git@master#egg=pyblockcypher
```
(for python 2.x use `pip` instead of `pip3`)

You can of course install it the old fashioned way like this:
```
$ python setup.py install
```

PyPI support coming soon.

#### Get Started:

```
>>> import blockcypher
```

How much bitcoin is currently sitting in the Bitcoin Foundation Address:
```
>>> blockcypher.get_total_balance('1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW')  # BTC unless specified otherwise
5850576658
```

Satoshis are a bit hard to inuit. What's that in BTC?
```
>>> blockcypher.satoshis_to_btc_rounded(5850576658)
58.5058
```
~58.5 BTC, not bad.

How many transactions did it take to accumulate that much BTC?
```
>>> blockcypher.get_total_num_transactions('1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW')  # BTC unless specified otherwise
```
(We could break that down with `get_num_confirmed_transactions()` and `get_num_unconfirmed_transactions()` if we wanted.

What's the current block height?
```
>>> blockcypher.get_latest_block_height()  # BTC unless specified otherwise
330545
```

We could get that as a block hash if we prefer:
```
>>> blockcypher.get_latest_block_hash()  # BTC unless specified otherwise
'0000000000000000126fc62619701b8c3da59424755e9de409053524620b114d'
```

We can also convert between block hashes and block heights
```
>>> blockcypher.get_block_height('0000000000000000126fc62619701b8c3da59424755e9de409053524620b114d')  # BTC unless specified otherwise
330545

```
Use `get-block_hash()` to convert back.

We can also find the previous block hash:
```
>>> blockcypher.get_prev_block_hash('0000000000000000126fc62619701b8c3da59424755e9de409053524620b114d')  # BTC unless specified otherwise

'000000000000000008573d8ac6eb85ea50fc164c2339dffeeb768423b72f5eeb'
```

Want to know about an address generally?
```
>>> blockcypher.get_address_details('1PTUHs5ivGAN5aHTY7UQk5RcCE8a67mUT4')  # BTC unless specified otherwise
{'unconfirmed_balance': 0,
 'final_balance': 6444,
 'address': '1PTUHs5ivGAN5aHTY7UQk5RcCE8a67mUT4',
 'tx_url': 'https://api.blockcypher.com/v1/btc/main/txs/',
 'unconfirmed_n_tx': 0,
 'unconfirmed_txrefs': [],
 'n_tx': 1,
 'final_n_tx': 1,
 'balance': 6444,
 'txrefs': [{'confirmations': 216,
   'tx_input_n': -1,
   'block_height': 330554,
   'tx_hash': '608cbc04cbda960e5b8481013030ff6cc6e4b92eeddf42d8dd15d42715c886f2',
   'double_spend': False,
   'value': 6444,
   'tx_output_n': 0,
   'confirmed': datetime.datetime(2014, 11, 18, 9, 39, 56, tzinfo=tzutc()),
   'spent': False}]}
```

Want to know about a transaction generally?
```
>>> blockcypher.get_transaction_details('fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157')  # BTC unless specified otherwise
{'confirmations': 318425,
 'lock_time': 0,
 'vout_sz': 1,
 'preference': 'low',
 'block_hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
 'block_height': 12345,
 'total': 5000000000,
 'confirmed': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'vin_sz': 1,
 'relayed_by': '',
 'received': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'fees': 0,
 'outputs': [{'value': 5000000000,
   'script': '4104c5d62274610e82819939c3341a4addc72634664d73b11ba761de42839aa3496f93b3b3ee80e497eb5a68439b02f04e9aeb1604fbcaa074aa82f0f7574f9f110dac',
   'script_type': 'pay-to-pubkey',
   'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
   'spent_by': ''}],
 'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
 'ver': 1,
 'double_spend': False,
 'inputs': [{'script_type': 'empty',
   'script': '04ffff001d02aa06',
   'output_index': -1,
   'output_value': 5000000000,
   'addresses': []}],
 'hash': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157'}
```
Some great transaction methods that take a transaction hash and return exactly what they sound like:
- ```get_num_confirmations()```
- ```get_satoshis_transacted()```
- ```get_satoshis_in_fees()```
- ```get_confidence()```, ```get_miner_preference()``` and ```get_receive_count()``` are powerful methods that use blockcypher's unique transaction confirmation prediction abilities.

Want more info about a block?
```
>>> blockcypher.get_block_overview(12345)  # BTC unless specified otherwise
{'txids': ['fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157'],
 'mrkl_root': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157',
 'height': 12345,
 'prev_block': '0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'total': 0,
 'time': datetime.datetime(2009, 4, 26, 22, 25, 32, tzinfo=tzutc()),
 'nonce': 784807199,
 'bits': 486604799,
 'fees': 0,
 'received_time': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'depth': 318424,
 'prev_block_url': 'https://api.blockcypher.com/v1/btc/main/blocks/0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'chain': 'BTC.main',
 'ver': 1,
 'n_tx': 1,
 'hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
 'tx_url': 'https://api.blockcypher.com/v1/btc/main/txs/'}
```

We can also get details on its transaction(s):
```
>>> blockcypher.get_block_details(12345)  # BTC unless specified otherwise
{'txids': [{'confirmations': 318425,
   'lock_time': 0,
   'vout_sz': 1,
   'preference': 'low',
   'block_hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
   'block_height': 12345,
   'total': 5000000000,
   'confirmed': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
   'vin_sz': 1,
   'relayed_by': '',
   'received': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
   'fees': 0,
   'outputs': [{'value': 5000000000,
     'script': '4104c5d62274610e82819939c3341a4addc72634664d73b11ba761de42839aa3496f93b3b3ee80e497eb5a68439b02f04e9aeb1604fbcaa074aa82f0f7574f9f110dac',
     'script_type': 'pay-to-pubkey',
     'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
     'spent_by': ''}],
   'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
   'ver': 1,
   'double_spend': False,
   'inputs': [{'script_type': 'empty',
     'script': '04ffff001d02aa06',
     'output_index': -1,
     'output_value': 5000000000,
     'addresses': []}],
   'hash': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157'}],
 'mrkl_root': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157',
 'height': 12345,
 'prev_block': '0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'total': 0,
 'time': datetime.datetime(2009, 4, 26, 22, 25, 32, tzinfo=tzutc()),
 'nonce': 784807199,
 'bits': 486604799,
 'fees': 0,
 'received_time': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'depth': 318424,
 'prev_block_url': 'https://api.blockcypher.com/v1/btc/main/blocks/0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'chain': 'BTC.main',
 'ver': 1,
 'n_tx': 1,
 'hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
 'tx_url': 'https://api.blockcypher.com/v1/btc/main/txs/'}
```

###### Coins Available
```
>>> from blockcypher import constants
>>> constants.COIN_SYMBOL_LIST
['btc', 'btc-testnet', 'ltc', 'doge', 'uro', 'bcy']
```

`btc` will always be assumed if nothing else is specified, but all methods support swapping in any of the previous `coin_symbol` entries.

For example, here's the latest Litecoin block height.
```
>>> blockcypher.get_latest_block_height(coin_symbol='ltc')
678686
```

#### More docs coming soon!
