from .utils import (is_valid_address, is_valid_hash,
        is_valid_block_representation, is_valid_coin_symbol)

from .constants import COIN_SYMBOL_MAPPINGS, DEBUG_MODE

from dateutil import parser

import requests
import json


def get_address_url(address, coin_symbol='btc'):
    '''
    Takes an address and coin_symbol and returns the blockcypher address URL

    Basic URL, more advanced URLs are possible
    '''
    assert(coin_symbol)
    assert(address)

    return 'https://api.blockcypher.com/v1/%s/%s/addrs/%s' % (
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
        address)


def get_address_details(address, coin_symbol='btc', txn_limit=None,
        api_key=None):
    '''
    Takes an address, coin_symbol and txn_limit (optional) and return the
    address details
    '''

    # This check appears to work for other blockchains
    # TODO: verify and/or improve
    assert is_valid_address(address)
    assert is_valid_coin_symbol(coin_symbol)

    url = get_address_url(address=address, coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if txn_limit:
        params['limit'] = txn_limit
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True)

    response_dict = json.loads(r.text)

    confirmed_txrefs = []
    for confirmed_txref in response_dict.get('txrefs', []):
        confirmed_txref['confirmed'] = parser.parse(confirmed_txref['confirmed'])
        confirmed_txrefs.append(confirmed_txref)
    response_dict['txrefs'] = confirmed_txrefs

    unconfirmed_txrefs = []
    for unconfirmed_txref in response_dict.get('unconfirmed_txrefs', []):
        unconfirmed_txref['received'] = parser.parse(unconfirmed_txref['received'])
        unconfirmed_txrefs.append(unconfirmed_txref)
    response_dict['unconfirmed_txrefs'] = unconfirmed_txrefs

    return response_dict


def get_transaction_url(tx_hash, coin_symbol='btc'):
    '''
    Takes a tx_hash and coin_symbol and returns the blockcypher transaction URL

    Basic URL, more advanced URLs are possible
    '''

    assert is_valid_hash(tx_hash)
    assert is_valid_coin_symbol(coin_symbol)

    return 'https://api.blockcypher.com/v1/%s/%s/txs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            tx_hash,
            )


def get_transaction_details(tx_hash, coin_symbol='btc', limit=None,
        api_key=None):
    """
    Takes a tx_hash, coin_symbol, and limit and returns the transaction details

    Limit applies to both num inputs and num outputs.
    TODO: add offsetting once supported
    """

    assert is_valid_hash(tx_hash)
    assert is_valid_coin_symbol(coin_symbol)

    url = get_transaction_url(tx_hash=tx_hash, coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if limit:
        params['limit'] = limit

    r = requests.get(url, params=params, verify=True)

    response_dict = json.loads(r.text)

    if not 'error' in response_dict:
        if response_dict['block_height'] > 0:
            response_dict['confirmed'] = parser.parse(response_dict['confirmed'])
        else:
            # Blockcypher reports fake times if it's not in a block
            response_dict['confirmed'] = None
            response_dict['block_height'] = None

        # format this string as a datetime object
        response_dict['received'] = parser.parse(response_dict['received'])

    return response_dict


def get_block_overview_url(block_representation, coin_symbol='btc'):
    '''
    Takse a block_representation and coin_symbol and returns the block
    overview URL
    '''

    assert is_valid_coin_symbol(coin_symbol)

    return 'https://api.blockcypher.com/v1/%s/%s/blocks/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            block_representation,
            )


def get_block_overview(block_representation, coin_symbol='btc', txn_limit=None,
        txn_offset=None, api_key=None):
    """
    Takes a block_representation, coin_symbol and txn_limit and gets an overview
    of that block, including up to X transaction ids.

    Note that block_representation may be the block number or block hash
    """

    assert is_valid_coin_symbol(coin_symbol)
    assert is_valid_block_representation(
            block_representation=block_representation,
            coin_symbol=coin_symbol)

    url = get_block_overview_url(
            block_representation=block_representation,
            coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if txn_limit:
        params['limit'] = txn_limit
    if txn_offset:
        params['txstart'] = txn_offset

    r = requests.get(url, params=params, verify=True)

    response_dict = json.loads(r.text)

    response_dict['received_time'] = parser.parse(response_dict['received_time'])
    response_dict['time'] = parser.parse(response_dict['time'])

    return response_dict


def get_block_details(block_representation, coin_symbol='btc', txn_limit=None,
        txn_offset=None, api_key=None):
    """
    Takes a block_representation, coin_symbol and txn_limit and
    1) Gets the block overview
    2) Makes a separate API call to get specific data on txn_limit transactions

    Note: block_representation may be the block number or block hash

    WARNING: using a high txn_limit will make this *extremely* slow.
    """

    assert is_valid_coin_symbol(coin_symbol)

    block_overview = get_block_overview(
            block_representation=block_representation,
            coin_symbol=coin_symbol,
            txn_limit=txn_limit,
            txn_offset=txn_offset,
            api_key=api_key,
            )

    txs_full = []
    for txid in block_overview['txids']:
        tx_details = get_transaction_details(
                tx_hash=txid,
                coin_symbol=coin_symbol,
                limit=100,  # arbitrary, but a pretty large number
                )
        txs_full.append(tx_details)
    block_overview['txids'] = txs_full

    return block_overview


def get_blockchain_overview_url(coin_symbol='btc'):
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def get_latest_block_height(coin_symbol='btc', api_key=None):

    assert is_valid_coin_symbol(coin_symbol)

    url = get_blockchain_overview_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True)

    response_dict = json.loads(r.text)

    return response_dict['height']


def get_websocket_url(coin_symbol):

    # TODO: add ability to include an api_key

    assert is_valid_coin_symbol(coin_symbol)

    return 'wss://socket.blockcypher.com/v1/%s/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
