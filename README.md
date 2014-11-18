pyblockcypher
=============

Python library for the BlockCypher web services

Currently in beta, more features and support for more endpoints coming soon.

Issues and pull requests much appreciated!

Handles datetime conversions. Designed to be used without having to RTFM.

*Should* support python 2.6+ and python3.x, but hasn't been thoroughly tested. Please file an issue if something isn't working.

#### Installation (pypy coming soon):
```
$ python setup.py install
```
#### Get Started:

```
>>> import blockcypher
>>> import pprint  # for demo purposes, not needed for your code
```

Let's start with something simple, what's the current block height?
```
>>> blockcypher.get_latest_block_height()  # BTC unless specified otherwise
330545
```

We could get that as a block hash if we prefer:
```
>>> blockcypher.get_latest_block_hash()  # BTC unless specified otherwise
'0000000000000000126fc62619701b8c3da59424755e9de409053524620b114d'
```
Want to know about an address?
```
>>> address_details = blockcypher.get_address_details('1PTUHs5ivGAN5aHTY7UQk5RcCE8a67mUT4')  # BTC unless specified otherwise
>>> pprint.pprint(address_details, width=1)
{'address': '1PTUHs5ivGAN5aHTY7UQk5RcCE8a67mUT4',
 'balance': 0,
 'final_balance': 6444,
 'final_n_tx': 1,
 'n_tx': 0,
 'tx_url': 'https://api.blockcypher.com/v1/btc/main/txs/',
 'txrefs': [],
 'unconfirmed_balance': 6444,
 'unconfirmed_n_tx': 1,
 'unconfirmed_txrefs': [{'confidence': 0.9990183563703441,
                         'confirmations': 0,
                         'double_spend': False,
                         'preference': 'medium',
                         'receive_count': 642,
                         'received': datetime.datetime(2014, 11, 18, 9, 36, 30, 864054, tzinfo=tzutc()),
                         'spent': False,
                         'tx_hash': '608cbc04cbda960e5b8481013030ff6cc6e4b92eeddf42d8dd15d42715c886f2',
                         'tx_input_n': -1,
                         'tx_output_n': 0,
                         'value': 6444}]}
```
Want to know about a specific transaction?
```
>>> transaction_details = blockcypher.get_transaction_details('fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157')
>>> pprint.pprint(transaction_details, width=1)
{'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
 'block_hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
 'block_height': 12345,
 'confirmations': 318209,
 'confirmed': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'double_spend': False,
 'fees': 0,
 'hash': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157',
 'inputs': [{'addresses': [],
             'output_index': -1,
             'output_value': 5000000000,
             'script': '04ffff001d02aa06',
             'script_type': 'empty'}],
 'lock_time': 0,
 'outputs': [{'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
              'script': '4104c5d62274610e82819939c3341a4addc72634664d73b11ba761de42839aa3496f93b3b3ee80e497eb5a68439b02f04e9aeb1604fbcaa074aa82f0f7574f9f110dac',
              'script_type': 'pay-to-pubkey',
              'spent_by': '',
              'value': 5000000000}],
 'preference': 'low',
 'received': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'relayed_by': '',
 'total': 5000000000,
 'ver': 1,
 'vin_sz': 1,
 'vout_sz': 1}

```

Want more info about a block?
```
>>> block12345_details = blockcypher.get_block_overview(12345)  # BTC by default
>>> pprint.pprint(block12345_details, width=1)
{'bits': 486604799,
 'chain': 'BTC.main',
 'depth': 318202,
 'fees': 0,
 'hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
 'height': 12345,
 'mrkl_root': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157',
 'n_tx': 1,
 'nonce': 784807199,
 'prev_block': '0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'prev_block_url': 'https://api.blockcypher.com/v1/btc/main/blocks/0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'received_time': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'time': datetime.datetime(2009, 4, 26, 22, 25, 32, tzinfo=tzutc()),
 'total': 0,
 'tx_url': 'https://api.blockcypher.com/v1/btc/main/txs/',
 'txids': ['fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157'],
 'ver': 1}

```

We can also get details on its transactions:
```
>>> block12345_details = blockcypher.get_block_details(12345)
>>> pprint.pprint(block12345_details, width=1)
{'bits': 486604799,
 'chain': 'BTC.main',
 'depth': 318203,
 'fees': 0,
 'hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
 'height': 12345,
 'mrkl_root': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157',
 'n_tx': 1,
 'nonce': 784807199,
 'prev_block': '0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'prev_block_url': 'https://api.blockcypher.com/v1/btc/main/blocks/0000000076876082384460fb5a231cc5a5e874b9762e15a4e7b1fc068f749cdf',
 'received_time': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
 'time': datetime.datetime(2009, 4, 26, 22, 25, 32, tzinfo=tzutc()),
 'total': 0,
 'tx_url': 'https://api.blockcypher.com/v1/btc/main/txs/',
 'txids': [{'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
            'block_hash': '00000000b8980ec1fe96bc1b4425788ddc88dd36699521a448ebca2020b38699',
            'block_height': 12345,
            'confirmations': 318204,
            'confirmed': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
            'double_spend': False,
            'fees': 0,
            'hash': 'fd1dc97a826eb93b485b6bada84a807ee81181f7ab2720cefb5fa96729363157',
            'inputs': [{'addresses': [],
                        'output_index': -1,
                        'output_value': 5000000000,
                        'script': '04ffff001d02aa06',
                        'script_type': 'empty'}],
            'lock_time': 0,
            'outputs': [{'addresses': ['18x6rfvHEgH1iTbkJTjRpYJrfSAhWdUiQM'],
                         'script': '4104c5d62274610e82819939c3341a4addc72634664d73b11ba761de42839aa3496f93b3b3ee80e497eb5a68439b02f04e9aeb1604fbcaa074aa82f0f7574f9f110dac',
                         'script_type': 'pay-to-pubkey',
                         'spent_by': '',
                         'value': 5000000000}],
            'preference': 'low',
            'received': datetime.datetime(2014, 5, 19, 19, 39, 12, 207000, tzinfo=tzutc()),
            'relayed_by': '',
            'total': 5000000000,
            'ver': 1,
            'vin_sz': 1,
            'vout_sz': 1}],
 'ver': 1}

```

###### Coins Available
```
>>> blockcypher.COIN_SYMBOL_LIST
['btc', 'btc-testnet', 'ltc', 'doge', 'uro', 'bcy']
```

`btc` will always be assumed if nothing else is specified.

All methods support swapping in any of the previous `coin_symbol` entries.
```
>>> blockcypher.get_latest_block_height(coin_symbol='ltc')
678686

```


#### More docs coming soon!
