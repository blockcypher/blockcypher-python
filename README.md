pyblockcypher
=============

Python library for the BlockCypher web services

#### Installation (pypy coming soon):
```
$ python setup.py install
```
#### Get Started:

```
>>> import blockcypher
>>> import pprint  # for demo purposes, not needed for your code

>>> blockcypher.get_latest_block_height()  # BTC by default
330545

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
