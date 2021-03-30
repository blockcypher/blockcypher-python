blockcypher-python
=============

Official python library for BlockCypher web services. Easily query the blockchain without writing any code. Fast, reliable, and packed with powerful features you won't find in other block explorers. Currently supports bitcoin (including main and testnet), Litecoin, Dogecoin, Dash, URO and the blockcypher testnet.

Designed to be used without having to RTFM.

More features and support for more endpoints coming soon. Should support python 2.6+ and python3.x, but hasn't been thoroughly tested on 2.6+. Native support for datetime conversions. Issues and pull requests much appreciated!

![](https://github.com/blockcypher/blockcypher-python/workflows/Continuous%20Integration/badge.svg)

#### Installation

Use pip with
```
$ pip3 install blockcypher
```
(for python 2.x use `pip` instead of `pip3`)

You can of course install it the old fashioned way like this:
```
$ python setup.py install
```

#### Get Started:

```
>>> import blockcypher
```
Note: to keep your code clean we recommend `from blockcypher import foo` where `foo` is the method you want to use, but for simplicity all examples below are instead written as `blockcypher.foo('bar')`

How much bitcoin (in satoshis) is currently sitting in the Bitcoin Foundation Address:
```
>>> blockcypher.get_total_balance('1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW')  # BTC unless specified otherwise
5850576658
```

Satoshis are a bit hard to inuit. How much is that in BTC?
```
>>> blockcypher.from_base_unit(5850576658, 'btc')
58.50576658
```
~58.5 BTC, not bad.

How many transactions did it take to accumulate that much BTC?
```
>>> blockcypher.get_total_num_transactions('1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW')  # BTC unless specified otherwise
901
```
We could break that down with `get_num_confirmed_transactions()` and `get_num_unconfirmed_transactions()` if we wanted.

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
Use `get_block_hash()` to convert back.

We can also find the previous block hash:
```
>>> blockcypher.get_prev_block_hash('0000000000000000126fc62619701b8c3da59424755e9de409053524620b114d')  # BTC unless specified otherwise
'000000000000000008573d8ac6eb85ea50fc164c2339dffeeb768423b72f5eeb'
```

#### Something Cool

Payment forwarding is really hard to setup yourself and trivial with blockcypher.

```
>>> blockcypher.get_forwarding_address('16uKw7GsQSzfMaVTcT7tpFQkd7Rh9qcXWX', api_key='your key here')  # BTC unless specified otherwise
'1Am4RUsCoiC3LfVC53kxVyfPkB4gEdRtkg'
```

Now any funds sent to `1Am4RUsCoiC3LfVC53kxVyfPkB4gEdRtkg` will instantly forward to `16uKw7GsQSzfMaVTcT7tpFQkd7Rh9qcXWX`.

You can check on your payments like this:
```
>>> blockcypher.list_forwarding_addresses(api_key='your key here', coin_symbol='btc')
[{'token': '8d99...',
  'id': '60ad7de3-ce81-40a2-ac92-6c74ab85bb72',
  'txs': ['f7750e98af49d12b2c63835399d4a96e1b5fd76f897d020f6c6bf8a7c13cdae1'],
  'input_address': '162r...',
  'callback_url': 'http://requestb.in/...',
  'destination': '1BaJ...'},
...
]
```

And you can delete one like this:
```
>>> blockcypher.delete_forwarding_address(payment_id='60ad7de3-ce81-40a2-ac92-6c74ab85bb72')  # BTC unless specified otherwise

```

#### The Details

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

You can also get a list of broadcast transactions that haven't made it into a block yet:
```
>>> blockcypher.get_broadcast_transaction_hashes(limit=5)
['4d6e75ed639fc7fe63f57b5578fd01e6712d22f1f307dc1bf720fddc59b4d586',
 'daae0f0849148b512fb909d57444a9f41300f188c9583ff93e71c8b97546ebd6',
 '899d1e1dd41baacf7b766fc643156e40d2438d780dd00ec651c9312693e3fe16',
 '313dfba9bd69d406176e5b305146a3136f40eda4589f06e1d770d6bfacaf5b52',
 'c3e0a3a702a4b8cd6f72618fd13e87b7f2b55a215fd78c35ca13a2d2bbd89088']
```
For more details on those transactions, use `blockcypher.get_broadcast_transactions()`

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

Another cool feature is that we can generate a new address keypair server-side, but you should really do this client-side:
```
>>> blockcypher.generate_new_address()
{'public': '03c87d1bba027204670c975d01e813d4a20ba4f79500802ba0d51ce3393fb86c1f',
 'private': '6a16a2b20e56b7ab8fa366023787730ded6ee9cbd6d37d3e3af5a6bed551b721',
 'address': '12TiM15S5MFgYLfphaou2VZkmgyMDrfH8V'}
```
(If you use this exact bitcoin address, expect to lose your money instantly!)

#### Many More Coins Available
```
>>> from blockcypher import constants
>>> constants.COIN_SYMBOL_LIST
['btc', 'btc-testnet', 'ltc', 'doge', 'dash', 'bcy']
```

`btc` will always be assumed if nothing else is specified, but all methods support swapping in any of the previous `coin_symbol` entries. Just pass `coin_symbol='foo'` as a keyword argument to the function.

For example, here's the latest Litecoin block height.
```
>>> blockcypher.get_latest_block_height(coin_symbol='ltc')
678686
```

#### More examples
See the official blockcypher docs at https://blockcypher.com/dev/bitcoin?python#

#### Pull Requests Welcome
Please note that all PRs require test coverage in `test_blockcypher.py`.
