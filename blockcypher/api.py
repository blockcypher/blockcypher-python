from .utils import (is_valid_address, is_valid_hash,
        is_valid_block_representation, is_valid_coin_symbol,
        is_valid_address_for_coinsymbol)

from .constants import COIN_SYMBOL_MAPPINGS, DEBUG_MODE

from dateutil import parser

import requests
import json


TIMEOUT_IN_SECONDS = 20


def get_address_details_url(address, coin_symbol='btc'):
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


def get_addresses_details_url(address_list, coin_symbol='btc'):
    '''
    Takes a list of addresses and coin_symbol and returns the blockcypher address URL

    Basic URL, more advanced URLs are possible
    '''
    assert(coin_symbol)
    assert(address_list)

    return 'https://api.blockcypher.com/v1/%s/%s/addrs/%s' % (
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
        ';'.join(address_list),
        )


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

    url = get_address_details_url(address=address, coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if txn_limit:
        params['limit'] = txn_limit
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

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


def get_addresses_details(address_list, coin_symbol='btc', txn_limit=None,
        api_key=None):
    '''
    Takes a list of addresses, coin_symbol and txn_limit (optional) and return the
    address details
    '''

    for address in address_list:
        assert is_valid_address_for_coinsymbol(
                b58_address=address,
                coin_symbol=coin_symbol)

    url = get_addresses_details_url(address_list=address_list, coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if txn_limit:
        params['limit'] = txn_limit
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict_list = json.loads(r.text)
    cleaned_dict_list = []

    for response_dict in response_dict_list:
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

        cleaned_dict_list.append(response_dict)

    return cleaned_dict_list


def get_address_overview_url(address, coin_symbol='btc'):
    '''
    Takes an address and coin_symbol and returns the blockcypher address URL

    Basic URL, more advanced URLs are possible
    '''
    assert(coin_symbol)
    assert(address)

    return 'https://api.blockcypher.com/v1/%s/%s/addrs/%s/balance' % (
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
        address)


def get_address_overview(address, coin_symbol='btc', api_key=None):
    '''
    Takes an address and coin_symbol and return the address details
    '''

    assert is_valid_address_for_coinsymbol(b58_address=address,
            coin_symbol=coin_symbol)

    url = get_address_overview_url(address=address, coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return json.loads(r.text)


def get_total_balance(address, coin_symbol='btc', api_key=None):
    '''
    Balance including confirmed and unconfirmed transactions for this address,
    in satoshi.
    '''
    return get_address_overview(address=address,
            coin_symbol=coin_symbol)['final_balance']


def get_unconfirmed_balance(address, coin_symbol='btc', api_key=None):
    '''
    Balance including only unconfirmed (0 block) transactions for this address,
    in satoshi.
    '''
    return get_address_overview(address=address,
            coin_symbol=coin_symbol)['unconfirmed_balance']


def get_confirmed_balance(address, coin_symbol='btc', api_key=None):
    '''
    Balance including only confirmed (1+ block) transactions for this address,
    in satoshi.
    '''
    return get_address_overview(address=address,
            coin_symbol=coin_symbol)['balance']


def get_num_confirmed_transactions(address, coin_symbol='btc', api_key=None):
    '''
    Only transactions that have made it into a block (confirmations > 0)
    '''
    return get_address_overview(address=address,
            coin_symbol=coin_symbol)['n_tx']


def get_num_unconfirmed_transactions(address, coin_symbol='btc', api_key=None):
    '''
    Only transactions that have note made it into a block (confirmations == 0)
    '''
    return get_address_overview(address=address,
            coin_symbol=coin_symbol)['unconfirmed_n_tx']


def get_total_num_transactions(address, coin_symbol='btc', api_key=None):
    '''
    All transaction, regardless if they have made it into any blocks
    '''
    return get_address_overview(address=address,
            coin_symbol=coin_symbol)['final_n_tx']


def get_address_generation_url(coin_symbol='btc'):
    '''
    Takes a coin_symbol and returns the blockcypher address generation URL
    '''
    assert(coin_symbol)

    return 'https://api.blockcypher.com/v1/%s/%s/addrs' % (
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
        COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
        )


def generate_new_address(coin_symbol='btc', api_key=None):
    '''
    Takes a coin_symbol and returns a new address with it's public and private keys

    This method will create the address server side. If you want to create a secure
    address client-side using python, please check out the new_random_wallet()
    method in https://github.com/sbuss/bitmerchant
    '''

    # This check appears to work for other blockchains
    # TODO: verify and/or improve
    assert is_valid_coin_symbol(coin_symbol)

    url = get_address_generation_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.post(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return json.loads(r.text)


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


def get_transactions_url(tx_hash_list, coin_symbol='btc', api_key=None):
    '''
    Takes a list of tx_hashes and a coin_symbol and returns the blockcypher transaction URL

    Basic URL, more advanced URLs are possible
    '''

    for tx_hash in tx_hash_list:
        assert is_valid_hash(tx_hash)
    assert is_valid_coin_symbol(coin_symbol)

    return 'https://api.blockcypher.com/v1/%s/%s/txs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            ';'.join(tx_hash_list),
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

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

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


def get_transactions_details(tx_hash_list, coin_symbol='btc', limit=None,
        api_key=None):
    """
    Takes a list of tx_hashes, coin_symbol, and limit and returns the transaction details

    Limit applies to both num inputs and num outputs.
    TODO: add offsetting once supported
    """

    for tx_hash in tx_hash_list:
        assert is_valid_hash(tx_hash)
    assert is_valid_coin_symbol(coin_symbol)

    url = get_transactions_url(tx_hash_list=tx_hash_list, coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if limit:
        params['limit'] = limit

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict_list = json.loads(r.text)
    cleaned_dict_list = []

    for response_dict in response_dict_list:
        if not 'error' in response_dict:
            if response_dict['block_height'] > 0:
                response_dict['confirmed'] = parser.parse(response_dict['confirmed'])
            else:
                # Blockcypher reports fake times if it's not in a block
                response_dict['confirmed'] = None
                response_dict['block_height'] = None

            # format this string as a datetime object
            response_dict['received'] = parser.parse(response_dict['received'])
        cleaned_dict_list.append(response_dict)

    return cleaned_dict_list


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

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = json.loads(r.text)

    unconfirmed_txs = []
    for unconfirmed_tx in response_dict:
        unconfirmed_tx['received'] = parser.parse(unconfirmed_tx['received'])
        unconfirmed_txs.append(unconfirmed_tx)
    return unconfirmed_txs


def get_broadcast_transaction_hashes(coin_symbol='btc', api_key=None, limit=10):
    '''
    Warning, slow!
    '''
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


def get_blocks_overview_url(block_representation_list, coin_symbol='btc'):
    '''
    Takse a block_representation and coin_symbol and returns the block
    overview URL
    '''

    assert is_valid_coin_symbol(coin_symbol)

    return 'https://api.blockcypher.com/v1/%s/%s/blocks/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            ';'.join([str(x) for x in block_representation_list]),
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

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = json.loads(r.text)

    response_dict['received_time'] = parser.parse(response_dict['received_time'])
    response_dict['time'] = parser.parse(response_dict['time'])

    return response_dict


def get_blocks_overview(block_representation_list, coin_symbol='btc',
        txn_limit=None, api_key=None):
    '''
    Batch request version of get_blocks_overview
    '''
    assert is_valid_coin_symbol(coin_symbol)
    for block_representation in block_representation_list:
        assert is_valid_block_representation(
                block_representation=block_representation,
                coin_symbol=coin_symbol)

    url = get_blocks_overview_url(
            block_representation_list=block_representation_list,
            coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if txn_limit:
        params['limit'] = txn_limit

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict_list = json.loads(r.text)

    cleaned_dict_list = []
    for response_dict in response_dict_list:
        response_dict['received_time'] = parser.parse(response_dict['received_time'])
        response_dict['time'] = parser.parse(response_dict['time'])
        cleaned_dict_list.append(response_dict)

    return cleaned_dict_list


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
    Takes a block_representation and returns the nonce
    '''
    return get_block_overview(block_representation=block_representation,
            coin_symbol=coin_symbol, txn_limit=1, api_key=api_key)['bits']


def get_prev_block_hash(block_representation, coin_symbol='btc', api_key=None):
    '''
    Takes a block_representation and returns the previous block hash
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

    tx_details = get_transactions_details(
            tx_hash_list=block_overview['txids'],
            coin_symbol=coin_symbol,
            limit=100,  # arbitrary, but a pretty large number
            api_key=api_key,
            )
    block_overview['txids'] = tx_details

    return block_overview


def get_blockchain_overview_url(coin_symbol='btc'):
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def get_latest_block_height(coin_symbol='btc', api_key=None):
    '''
    Get the latest block height for a given coin
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = get_blockchain_overview_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = json.loads(r.text)

    return response_dict['height']


def get_latest_block_hash(coin_symbol='btc', api_key=None):
    '''
    Get the latest block hash for a given coin
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = get_blockchain_overview_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

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


def get_forwarding_address_details(destination_address, api_key, callback_url=None,
        coin_symbol='btc'):
    """
    Give a destination address and return the details of the input address
    that will automatically forward to the destination address

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

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return json.loads(r.text)


def get_forwarding_address(destination_address, api_key, callback_url=None,
        coin_symbol='btc'):
    """
    Give a destination address and return an input address that will
    automatically forward to the destination address. See
    get_forwarding_address_details if you also need the forwarding address ID.

    Note: a blockcypher api_key is required for this method
    """

    resp_dict = get_forwarding_address_details(
            destination_address,
            api_key,
            callback_url=callback_url,
            coin_symbol=coin_symbol
            )

    return resp_dict['input_address']


def list_forwarding_addresses(api_key, coin_symbol='btc'):
    '''
    List the forwarding addresses for a certain api key
    (and on a specific blockchain)
    '''

    assert is_valid_coin_symbol(coin_symbol)
    assert api_key

    url = get_payments_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {'token': api_key}

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return json.loads(r.text)


def delete_forwarding_address(payment_id, coin_symbol='btc'):
    '''
    Delete a forwarding address on a specific blockchain, using its
    payment id
    '''

    assert payment_id
    assert is_valid_coin_symbol(coin_symbol)

    url = '%s/%s' % (get_payments_url(coin_symbol=coin_symbol), payment_id)

    if DEBUG_MODE:
        print(url)

    r = requests.delete(url, verify=True, timeout=TIMEOUT_IN_SECONDS)

    # TODO: update this to JSON once API is returning JSON
    return r.text


def get_webhook_url(coin_symbol='btc'):
    """
    Used for creating, listing and deleting payments
    """
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/hooks' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def subscribe_to_address_webhook(callback_url, subscription_address, coin_symbol='btc', api_key=None):
    '''
    Subscribe to transaction webhooks on a given address.
    Webhooks for transaction broadcast and each confirmation (up to 6).

    Returns the blockcypher ID of the subscription
    '''
    assert is_valid_coin_symbol(coin_symbol)
    assert is_valid_address_for_coinsymbol(subscription_address, coin_symbol)

    url = get_webhook_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {
            'event': 'tx-confirmation',
            'url': callback_url,
            'address': subscription_address,
            }

    if api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = json.loads(r.text)

    return response_dict['id']


def get_pushtx_url(coin_symbol='btc'):
    """
    Used for pushing hexadecimal transactions to the network
    """
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/txs/push' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def get_decodetx_url(coin_symbol='btc'):
    """
    Used for decoding hexadecimal transactions without broadcasting them
    """
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/txs/decode' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def pushtx(tx_hex, coin_symbol='btc', api_key=None):
    '''
    Takes a signed transaction hex binary (and coin_symbol) and broadcasts it to the bitcoin network.
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = get_pushtx_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {'tx': tx_hex}
    if api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return json.loads(r.text)


def decodetx(tx_hex, coin_symbol='btc', api_key=None):
    '''
    Takes a signed transaction hex binary (and coin_symbol) and decodes it to JSON.

    Does NOT broadcast the transaction to the bitcoin network.
    Especially useful for testing/debugging and sanity checking
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = get_decodetx_url(coin_symbol=coin_symbol)

    if DEBUG_MODE:
        print(url)

    params = {'tx': tx_hex}
    if api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return json.loads(r.text)


def send_bcy_faucet(address_to_fund, satoshis, api_key):
    '''
    Send yourself test coins on the blockcypher (not bitcoin) testnet

    You can see your balance info at https://live.blockcypher.com/bcy/
    '''
    assert is_valid_address(address_to_fund)
    assert satoshis > 0
    assert api_key

    url = 'http://api.blockcypher.com/v1/bcy/test/faucet'
    if DEBUG_MODE:
        print(url)

    data = {
            'address': address_to_fund,
            'amount': satoshis,
            }
    params = {
            'token': api_key,
            }

    r = requests.post(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)
    response_dict = json.loads(r.text)
    return response_dict['tx_ref']


def get_websocket_url(coin_symbol):

    assert is_valid_coin_symbol(coin_symbol)

    return 'wss://socket.blockcypher.com/v1/%s/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
