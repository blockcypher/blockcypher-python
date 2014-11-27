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

    r = requests.get(url, params=params, verify=True, timeout=20)

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


def get_unconfirmed_transactions(address, coin_symbol='btc', api_key=None):
    '''
    Return all unconfirmed transactions (not in any blocks) for a given address

    Limit is set to 100 transactions. If you have an address with > 100
    unconfirmed transactions, please write your own logic.
    '''
    return get_address_details(address=address, coin_symbol=coin_symbol,
            txn_limit=100)['final_balance']


def get_total_balance(address, coin_symbol='btc', api_key=None):
    '''
    Balance including confirmed and unconfirmed transactions for this address,
    in satoshi.
    '''
    return get_address_details(address=address,
            coin_symbol=coin_symbol)['final_balance']


def get_unconfirmed_balance(address, coin_symbol='btc', api_key=None):
    '''
    Balance including only unconfirmed (0 block) transactions for this address,
    in satoshi.
    '''
    return get_address_details(address=address,
            coin_symbol=coin_symbol)['unconfirmed_balance']


def get_confirmed_balance(address, coin_symbol='btc', api_key=None):
    '''
    Balance including only confirmed (1+ block) transactions for this address,
    in satoshi.
    '''
    return get_address_details(address=address,
            coin_symbol=coin_symbol)['balance']


def get_num_confirmed_transactions(address, coin_symbol='btc', api_key=None):
    '''
    Only transactions that have made it into a block (confirmations > 0)
    '''
    return get_address_details(address=address,
            coin_symbol=coin_symbol)['n_tx']


def get_num_unconfirmed_transactions(address, coin_symbol='btc', api_key=None):
    '''
    Only transactions that have note made it into a block (confirmations == 0)
    '''
    return get_address_details(address=address,
            coin_symbol=coin_symbol)['unconfirmed_n_tx']


def get_total_num_transactions(address, coin_symbol='btc', api_key=None):
    '''
    All transaction, regardless if they have made it into any blocks
    '''
    return get_address_details(address=address,
            coin_symbol=coin_symbol)['final_n_tx']


def get_transaction_url(tx_hash, coin_symbol='btc', api_key=None):
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

    r = requests.get(url, params=params, verify=True, timeout=20)

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


def get_num_confirmations(tx_hash, coin_symbol='btc', api_key=None):
    '''
    Given a tx_hash, return the number of confirmations that transactions has.

    Answer is going to be from 0 - current_block_height.
    '''
    return get_transaction_details(tx_hash=tx_hash, coin_symbol=coin_symbol,
            limit=1, api_key=api_key)['confirmations']


def get_confidence(tx_hash, coin_symbol='btc', api_key=None):
    return get_transaction_details(tx_hash=tx_hash, coin_symbol=coin_symbol,
            limit=1, api_key=api_key).get('confidence', 1)


def get_miner_preference(tx_hash, coin_symbol='btc', api_key=None):
    return get_transaction_details(tx_hash=tx_hash, coin_symbol=coin_symbol,
            limit=1, api_key=api_key).get('preference')


def get_receive_count(tx_hash, coin_symbol='btc', api_key=None):
    return get_transaction_details(tx_hash=tx_hash, coin_symbol=coin_symbol,
            limit=1, api_key=api_key).get('receive_count')


def get_satoshis_transacted(tx_hash, coin_symbol='btc', api_key=None):
    return get_transaction_details(tx_hash=tx_hash, coin_symbol=coin_symbol,
            limit=1, api_key=api_key)['total']


def get_satoshis_in_fees(tx_hash, coin_symbol='btc', api_key=None):
    return get_transaction_details(tx_hash=tx_hash, coin_symbol=coin_symbol,
            limit=1, api_key=api_key)['fees']


def get_broadcast_transactions_url(coin_symbol='btc'):
    return 'https://api.blockcypher.com/v1/%s/%s/txs/' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def get_broadcast_transactions(coin_symbol='btc', limit=10, api_key=None):
    """
    Get a list of broadcast but unconfirmed transactions
    Similar to bitcoind's getrawmempool method
    """

    url = get_broadcast_transactions_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if limit:
        params['limit'] = limit

    r = requests.get(url, params=params, verify=True, timeout=20)

    response_dict = json.loads(r.text)

    unconfirmed_txs = []
    for unconfirmed_tx in response_dict:
        unconfirmed_tx['received'] = parser.parse(unconfirmed_tx['received'])
        unconfirmed_txs.append(unconfirmed_tx)
    return unconfirmed_txs


def get_broadcast_transaction_hashes(coin_symbol='btc', api_key=None,
        limit=10):
    transactions = get_broadcast_transactions(coin_symbol=coin_symbol,
            api_key=api_key, limit=limit)
    return [tx['hash'] for tx in transactions]


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

    r = requests.get(url, params=params, verify=True, timeout=20)

    response_dict = json.loads(r.text)

    response_dict['received_time'] = parser.parse(response_dict['received_time'])
    response_dict['time'] = parser.parse(response_dict['time'])

    return response_dict


def get_merkle_root(block_representation, coin_symbol='btc', api_key=None):
    '''
    Takes a block_representation and returns the merkle root
    '''
    return get_block_overview(block_representation=block_representation,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['mrkl_root']


def get_bits(block_representation, coin_symbol='btc', api_key=None):
    '''
    Takes a block_representation and returns the number of bits
    '''
    return get_block_overview(block_representation=block_representation,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['bits']


def get_nonce(block_representation, coin_symbol='btc', api_key=None):
    '''
    Takes a block_representation and returns the number of bits
    '''
    return get_block_overview(block_representation=block_representation,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['bits']


def get_prev_block_hash(block_representation, coin_symbol='btc', api_key=None):
    '''
    Takes a block_representation and returns the number of bits
    '''
    return get_block_overview(block_representation=block_representation,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['prev_block']


def get_block_hash(block_height, coin_symbol='btc', api_key=None):
    '''
    Takes a block_height and returns the block_hash
    '''
    return get_block_overview(block_representation=block_height,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['hash']


def get_block_height(block_hash, coin_symbol='btc', api_key=None):
    '''
    Takes a block_hash and returns the block_height
    '''
    return get_block_overview(block_representation=block_hash,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['height']


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
                api_key=api_key,
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

    r = requests.get(url, params=params, verify=True, timeout=20)

    response_dict = json.loads(r.text)

    return response_dict['height']


def get_latest_block_hash(coin_symbol='btc', api_key=None):

    assert is_valid_coin_symbol(coin_symbol)

    url = get_blockchain_overview_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=20)

    response_dict = json.loads(r.text)

    return response_dict['hash']


def get_payments_url(coin_symbol='btc'):
    """
    Used for creating, listing and deleting payments
    """
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/payments' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def get_forwarding_address(destination_address, api_key=None,
        callback_url=None, coin_symbol='btc'):
    """
    Give a destination address and return an input address that will
    automatically forward to the destination address

    Note: a blockcypher api_key is required for this method
    """

    assert is_valid_coin_symbol(coin_symbol)
    assert api_key

    url = get_payments_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {
            'destination': destination_address,
            'token': api_key,
            }

    if callback_url:
        params['callback_url'] = callback_url

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=20)

    response_dict = json.loads(r.text)

    return response_dict['input_address']


def list_forwarding_addresses(api_key, coin_symbol='btc'):
    assert is_valid_coin_symbol(coin_symbol)
    assert api_key

    url = get_payments_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {'token': api_key}

    r = requests.get(url, params=params, verify=True, timeout=20)

    return json.loads(r.text)


def delete_forwarding_address(payment_id, coin_symbol='btc'):
    assert payment_id
    assert is_valid_coin_symbol(coin_symbol)

    url = '%s/%s' % (get_payments_url(coin_symbol=coin_symbol), payment_id)

    if DEBUG_MODE:
        print(url)

    r = requests.delete(url, verify=True, timeout=20)

    # TODO: update this to JSON once API is returning JSON
    return r.text


def get_websocket_url(coin_symbol):

    assert is_valid_coin_symbol(coin_symbol)

    return 'wss://socket.blockcypher.com/v1/%s/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
