from .utils import (is_valid_hash, is_valid_block_representation,
        is_valid_coin_symbol, is_valid_address_for_coinsymbol,
        coin_symbol_from_mkey, double_sha256, compress_txn_outputs,
        get_txn_outputs_dict)

from .constants import COIN_SYMBOL_MAPPINGS

from dateutil import parser

from bitcoin import (ecdsa_raw_sign, ecdsa_raw_verify, der_encode_sig,
        der_decode_sig)

import requests
import json

import logging


TIMEOUT_IN_SECONDS = 20


logger = logging.getLogger(__name__)

'''
# For debugging:
# https://docs.python.org/3/howto/logging.html#configuring-logging
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)
'''


def get_address_details(address, coin_symbol='btc', txn_limit=None,
        api_key=None, before_bh=None, confirmations=0):
    '''
    Takes an address and coin_symbol and returns the address details

    Optional:
      - txn_limit: # transactions to include
      - before_bh: filters response to only include transactions below before
      height in the blockchain.
      - confirmations: returns the balance and TXRefs that have this number
      of confirmations
    '''

    assert is_valid_address_for_coinsymbol(b58_address=address,
            coin_symbol=coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/addrs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            address)
    logger.info(url)

    params = {}
    if txn_limit:
        params['limit'] = txn_limit
    if api_key:
        params['token'] = api_key
    if before_bh:
        params['before_bh'] = before_bh
    if confirmations:
        params['confirmations'] = confirmations

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

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


def get_wallet_transactions(wallet_name, api_key, coin_symbol='btc',
        before_bh=None, txn_limit=None, confirmations=0):
    '''
    Takes a wallet, api_key, coin_symbol and returns the wallet's details

    Optional:
      - txn_limit: # transactions to include
      - before_bh: filters response to only include transactions below before
      height in the blockchain.
      - confirmations: returns the balance and TXRefs that have this number
      of confirmations
    '''

    assert len(wallet_name) <= 25, wallet_name
    assert api_key
    assert is_valid_coin_symbol(coin_symbol=coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/addrs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            wallet_name)
    logger.info(url)

    params = {}
    if txn_limit:
        params['limit'] = txn_limit
    if api_key:
        params['token'] = api_key
    if before_bh:
        params['before_bh'] = before_bh
    if confirmations:
        params['confirmations'] = confirmations

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

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

    url = 'https://api.blockcypher.com/v1/%s/%s/addrs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            ';'.join(address_list),
            )
    logger.info(url)

    params = {}
    if txn_limit:
        params['limit'] = txn_limit
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict_list = r.json()
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


def get_address_overview(address, coin_symbol='btc', api_key=None):
    '''
    Takes an address and coin_symbol and return the address details
    '''

    assert is_valid_address_for_coinsymbol(b58_address=address,
            coin_symbol=coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/addrs/%s/balance' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            address)
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


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


def generate_new_address(coin_symbol='btc', api_key=None):
    '''
    Takes a coin_symbol and returns a new address with it's public and private keys.

    This method will create the address server side, which is inherently insecure and should only be used for testing.

    If you want to create a secure address client-side using python, please check out bitmerchant:

        from bitmerchant.wallet import Wallet
        Wallet.new_random_wallet()

    https://github.com/sbuss/bitmerchant
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/addrs' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.post(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def derive_hd_address(api_key=None, wallet_name=None, num_addresses=1,
        subchain_index=None, coin_symbol='btc'):
    '''
    Returns a new address (without access to the private key) and adds it to
    your HD wallet (previously created using create_hd_wallet).

    This method will traverse/discover a new address server-side from your
    previously supplied extended public key, the server will never see your
    private key. It is therefor safe for production use.

    You may also include a subchain_index directive if your wallet has multiple
    subchain_indices and you'd like to specify which one should be traversed.
    '''

    assert is_valid_coin_symbol(coin_symbol)
    assert api_key, api_key
    assert wallet_name, wallet_name
    assert type(num_addresses) is int

    url = 'https://api.blockcypher.com/v1/%s/%s/wallets/hd/%s/addresses/derive' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            wallet_name,
            )
    logger.info(url)

    params = {'token': api_key}
    if subchain_index:
        params['subchain_index'] = subchain_index
    if num_addresses > 1:
        params['count'] = num_addresses

    r = requests.post(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def get_transaction_details(tx_hash, coin_symbol='btc', limit=None,
        api_key=None, include_hex=False):
    """
    Takes a tx_hash, coin_symbol, and limit and returns the transaction details

    Limit applies to both num inputs and num outputs.
    TODO: add offsetting once supported
    """

    assert is_valid_hash(tx_hash)
    assert is_valid_coin_symbol(coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/txs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            tx_hash,
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if limit:
        params['limit'] = limit
    if include_hex:
        params['includeHex'] = 'true'  # boolean True (proper) won't work

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

    if 'error' not in response_dict:
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

    if len(tx_hash_list) == 1:
        return [get_transaction_details(
                tx_hash=tx_hash_list[0],
                coin_symbol=coin_symbol,
                limit=limit,
                api_key=api_key
                ), ]

    url = 'https://api.blockcypher.com/v1/%s/%s/txs/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            ';'.join(tx_hash_list),
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if limit:
        params['limit'] = limit

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict_list = r.json()
    cleaned_dict_list = []

    for response_dict in response_dict_list:
        if 'error' not in response_dict:
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


def get_broadcast_transactions(coin_symbol='btc', limit=10, api_key=None):
    """
    Get a list of broadcast but unconfirmed transactions
    Similar to bitcoind's getrawmempool method
    """

    url = 'https://api.blockcypher.com/v1/%s/%s/txs/' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if limit:
        params['limit'] = limit

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

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

    url = 'https://api.blockcypher.com/v1/%s/%s/blocks/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            block_representation,
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if txn_limit:
        params['limit'] = txn_limit
    if txn_offset:
        params['txstart'] = txn_offset

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

    if 'error' in response_dict:
        return response_dict

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

    url = 'https://api.blockcypher.com/v1/%s/%s/blocks/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            ';'.join([str(x) for x in block_representation_list]),
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key
    if txn_limit:
        params['limit'] = txn_limit

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict_list = r.json()

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

    if 'error' in block_overview:
        return block_overview

    txids_to_lookup = block_overview['txids']

    txs_details = get_transactions_details(
            tx_hash_list=txids_to_lookup,
            coin_symbol=coin_symbol,
            limit=10,  # arbitrary, but a decently large number
            api_key=api_key,
            )

    if 'error' in txs_details:
        return txs_details

    # build comparator dict to use for fast sorting of batched results later
    txids_comparator_dict = {}
    for cnt, tx_id in enumerate(txids_to_lookup):
        txids_comparator_dict[tx_id] = cnt

    # sort results using comparator dict
    block_overview['txids'] = sorted(
            txs_details,
            key=lambda k: txids_comparator_dict.get(k.get('hash'), 9999),  # anything that fails goes last
            )

    return block_overview


def get_blockchain_overview(coin_symbol='btc', api_key=None):
    assert is_valid_coin_symbol(coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    params = {}
    if api_key:
        params['token'] = api_key

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

    response_dict['time'] = parser.parse(response_dict['time'])

    return response_dict


def get_latest_block_height(coin_symbol='btc', api_key=None):
    '''
    Get the latest block height for a given coin
    '''

    return get_blockchain_overview(coin_symbol=coin_symbol,
            api_key=api_key)['height']


def get_latest_block_hash(coin_symbol='btc', api_key=None):
    '''
    Get the latest block hash for a given coin
    '''

    return get_blockchain_overview(coin_symbol=coin_symbol,
            api_key=api_key)['hash']


def get_blockchain_fee_estimates(coin_symbol='btc', api_key=None):
    """
    Returns high, medium, and low fee estimates for a given blockchain.
    """
    overview = get_blockchain_overview(coin_symbol=coin_symbol, api_key=api_key)
    return {
            'high_fee_per_kb': overview['high_fee_per_kb'],
            'medium_fee_per_kb': overview['medium_fee_per_kb'],
            'low_fee_per_kb': overview['low_fee_per_kb'],
            }


def get_blockchain_high_fee(coin_symbol='btc', api_key=None):
    """
    Returns high fee estimate per kilobyte for a given blockchain.
    """
    return get_blockchain_overview(coin_symbol, api_key)['high_fee_per_kb']


def get_blockchain_medium_fee(coin_symbol='btc', api_key=None):
    """
    Returns medium fee estimate per kilobyte for a given blockchain.
    """
    return get_blockchain_overview(coin_symbol, api_key)['medium_fee_per_kb']


def get_blockchain_low_fee(coin_symbol='btc', api_key=None):
    """
    Returns low fee estimate per kilobyte for a given blockchain.
    """
    return get_blockchain_overview(coin_symbol, api_key)['low_fee_per_kb']


def _get_payments_url(coin_symbol='btc'):
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

    url = _get_payments_url(coin_symbol=coin_symbol)
    logger.info(url)

    params = {
            'destination': destination_address,
            'token': api_key,
            }

    if callback_url:
        params['callback_url'] = callback_url

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


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

    url = _get_payments_url(coin_symbol=coin_symbol)
    logger.info(url)

    params = {'token': api_key}

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def delete_forwarding_address(payment_id, coin_symbol='btc'):
    '''
    Delete a forwarding address on a specific blockchain, using its
    payment id
    '''

    assert payment_id
    assert is_valid_coin_symbol(coin_symbol)

    url = '%s/%s' % (_get_payments_url(coin_symbol=coin_symbol), payment_id)
    logger.info(url)

    r = requests.delete(url, verify=True, timeout=TIMEOUT_IN_SECONDS)

    # TODO: update this to JSON once API is returning JSON
    return r.text


def subscribe_to_address_webhook(callback_url, subscription_address,
        coin_symbol='btc', api_key=None):
    '''
    Subscribe to transaction webhooks on a given address.
    Webhooks for transaction broadcast and each confirmation (up to 6).

    Returns the blockcypher ID of the subscription
    '''
    assert is_valid_coin_symbol(coin_symbol)
    assert is_valid_address_for_coinsymbol(subscription_address, coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/hooks' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    params = {
            'event': 'tx-confirmation',
            'url': callback_url,
            'address': subscription_address,
            }

    if api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    response_dict = r.json()

    return response_dict['id']


def send_faucet_coins(address_to_fund, satoshis, api_key, coin_symbol='bcy'):
    '''
    Send yourself test coins on the bitcoin or blockcypher testnet

    You can see your balance info at:
    - https://live.blockcypher.com/bcy/ for BCY
    - https://live.blockcypher.com/btc-testnet/ for BTC Testnet
    '''
    assert coin_symbol in ('bcy', 'btc-testnet')
    assert is_valid_address_for_coinsymbol(b58_address=address_to_fund, coin_symbol=coin_symbol)
    assert satoshis > 0
    assert api_key

    url = 'http://api.blockcypher.com/v1/%s/%s/faucet' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    data = {
            'address': address_to_fund,
            'amount': satoshis,
            }
    params = {
            'token': api_key,
            }

    r = requests.post(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)
    return r.json()


def _get_websocket_url(coin_symbol):

    assert is_valid_coin_symbol(coin_symbol)

    return 'wss://socket.blockcypher.com/v1/%s/%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def _get_pushtx_url(coin_symbol='btc'):
    """
    Used for pushing hexadecimal transactions to the network
    """
    assert is_valid_coin_symbol(coin_symbol)
    return 'https://api.blockcypher.com/v1/%s/%s/txs/push' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )


def pushtx(tx_hex, coin_symbol='btc', api_key=None):
    '''
    Takes a signed transaction hex binary (and coin_symbol) and broadcasts it to the bitcoin network.
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = _get_pushtx_url(coin_symbol=coin_symbol)

    logger.info(url)

    params = {'tx': tx_hex}
    if api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def decodetx(tx_hex, coin_symbol='btc', api_key=None):
    '''
    Takes a signed transaction hex binary (and coin_symbol) and decodes it to JSON.

    Does NOT broadcast the transaction to the bitcoin network.
    Especially useful for testing/debugging and sanity checking
    '''

    assert is_valid_coin_symbol(coin_symbol)

    url = 'https://api.blockcypher.com/v1/%s/%s/txs/decode' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    params = {'tx': tx_hex}
    if api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def create_wallet_from_address(wallet_name, address, api_key, coin_symbol='btc'):
    '''
    Create a new wallet with one address

    You can add addresses with the add_address_to_wallet method below
    You can delete the wallet with the delete_wallet method below
    '''
    assert is_valid_address_for_coinsymbol(address, coin_symbol)
    assert api_key
    assert len(wallet_name) <= 25, wallet_name

    data = {
            'name': wallet_name,
            'addresses': [address, ],
            }
    params = {'token': api_key}

    url = 'https://api.blockcypher.com/v1/%s/%s/wallets' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    r = requests.post(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def create_hd_wallet(wallet_name, xpubkey, api_key, subchain_indices=[],
        coin_symbol='btc'):
    '''
    Create a new wallet from an extended pubkey (xpub... for BTC)

    You can delete the wallet with the delete_wallet method below
    '''
    inferred_coin_symbol = coin_symbol_from_mkey(mkey=xpubkey)
    if inferred_coin_symbol:
        assert inferred_coin_symbol == coin_symbol
    assert api_key
    assert len(wallet_name) <= 25, wallet_name

    data = {
            'name': wallet_name,
            'extended_public_key': xpubkey,
            }
    params = {'token': api_key}

    if subchain_indices:
        data['subchain_indexes'] = subchain_indices

    url = 'https://api.blockcypher.com/v1/%s/%s/wallets/hd' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    r = requests.post(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()


def get_wallet_addresses(wallet_name, api_key, is_hd_wallet=False, zero_balance=None, used=None, coin_symbol='btc'):
    '''
    Returns a list of wallet addresses as well as some meta-data
    '''
    assert is_valid_coin_symbol(coin_symbol)
    assert api_key
    assert len(wallet_name) <= 25, wallet_name
    assert zero_balance in (None, True, False)
    assert used in (None, True, False)

    params = {'token': api_key}
    url = 'https://api.blockcypher.com/v1/%s/%s/wallets/%s%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            'hd/' if is_hd_wallet else '',  # hack!
            wallet_name,
            )
    logger.info(url)

    if zero_balance is True:
        params['zerobalance'] = 'true'
    elif zero_balance is False:
        params['zerobalance'] = 'false'
    if used is True:
        params['used'] = 'true'
    elif used is False:
        params['used'] = 'false'

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)
    return r.json()


def get_wallet_balance(wallet_name, api_key, coin_symbol='btc'):
    '''
    This is particularly useful over get_wallet_transactions and
    get_wallet_addresses in cases where you have lots of addresses/transactions.
    Much less data to return.
    '''
    assert is_valid_coin_symbol(coin_symbol)
    assert api_key
    assert len(wallet_name) <= 25, wallet_name

    params = {'token': api_key}
    url = 'https://api.blockcypher.com/v1/%s/%s/addrs/%s/balance' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            wallet_name,
            )
    logger.info(url)

    r = requests.get(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)
    return r.json()


def get_latest_paths_from_hd_wallet_addresses(wallet_addresses):
    '''
    Returns a list of dicts like this (note these are full paths):

    [
        {'subchain_index': 0, 'latest_path': 'm/0/2', 'latest_address':  '1foo',},
        {'subchain_index': 1, 'latest_path': None, 'latest_address':  None,},
        ...
    ]

    Note that if there is no subchain_index, it will return a singleton list
    with a 'subchain_index' entry set to None.
    '''
    latest_paths = []
    for chain in wallet_addresses['chains']:
        latest_path = None
        latest_address = None
        if chain['chain_addresses']:
            latest_address = chain['chain_addresses'][-1].get('address')
            latest_path = chain['chain_addresses'][-1].get('path')

        latest_path_dict = {
                'latest_path': latest_path,
                'latest_address': latest_address,
                }

        if 'index' in chain:
            index = chain['index']
            latest_path_dict['subchain_index'] = index
        else:
            latest_path_dict['subchain_index'] = None

        latest_paths.append(latest_path_dict)

    return latest_paths


def add_address_to_wallet(wallet_name, address, api_key, coin_symbol='btc'):
    assert is_valid_address_for_coinsymbol(address, coin_symbol)
    assert api_key
    assert len(wallet_name) <= 25, wallet_name

    data = {'addresses': [address, ]}
    params = {'token': api_key}

    url = 'https://api.blockcypher.com/v1/%s/%s/wallets/%s/addresses' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            wallet_name,
            )
    logger.info(url)

    r = requests.post(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)
    return r.json()


def remove_address_from_wallet(wallet_name, address, api_key, coin_symbol='btc'):
    assert is_valid_address_for_coinsymbol(address, coin_symbol)
    assert api_key
    assert len(wallet_name) <= 25, wallet_name

    data = {'addresses': [address, ]}
    params = {'token': api_key}

    url = 'https://api.blockcypher.com/v1/%s/%s/wallets/%s/addresses' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            wallet_name,
            )
    logger.info(url)

    r = requests.delete(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    if r.status_code != 204:
        # Didn't work
        return r.json()


def delete_wallet(wallet_name, api_key, is_hd_wallet=False, coin_symbol='btc'):
    assert api_key
    assert len(wallet_name) <= 25, wallet_name

    params = {'token': api_key}
    url = 'https://api.blockcypher.com/v1/%s/%s/wallets/%s%s' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            'hd/' if is_hd_wallet else '',  # hack!
            wallet_name,
            )
    logger.info(url)

    r = requests.delete(url, params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)
    if r.status_code != 204:
        # Didn't work
        return r.json()


def create_unsigned_tx(inputs, outputs, change_address=None,
        include_tosigntx=False, verify_tosigntx=False, min_confirmations=0,
        preference='high', coin_symbol='btc', api_key=None):
    '''
    Create a new transaction to sign. Doesn't ask for or involve private keys.
    Behind the scenes, blockcypher will:
    1) Fetch unspent outputs
    2) Decide which make the most sense to consume for the given transaction
    3) Return an unsigned transaction for you to sign

    min_confirmations is the minimum number of confirmations an unspent output
    must have in order to be included in a transaction

    tosign_tx is the raw tx which can be decoded to verify the transaction
    you're signing matches what you want to sign. You can also verify:
    sha256(sha256(tosign_tx))== tosign

    verify_tosigntx will take the raw tx data in tosign_tx and run the
    verification for you and protect you against a malicious or compromised
    blockcypher server

    Inputs is a list of either:
    - {'address': '1abcxyz...'} that will be included in the TX
    - {'wallet_name': 'bar', 'wallet_token': 'yourtoken'} that was previously registered and will be used
      to choose which addresses/inputs are included in the TX

    Details here: http://dev.blockcypher.com/#generic_transactions
    '''

    # Lots of defensive checks
    assert type(inputs) is list, inputs
    assert type(outputs) is list, outputs
    assert len(inputs) >= 1, inputs
    assert len(outputs) >= 1, outputs

    inputs_cleaned = []
    for input_obj in inputs:
        # `input` is a reserved word
        if 'address' in input_obj:
            address = input_obj['address']
            assert is_valid_address_for_coinsymbol(
                    b58_address=address,
                    coin_symbol=coin_symbol,
                    ), address
            inputs_cleaned.append({
                'addresses': [address, ],
                })
        elif 'wallet_name' in input_obj and 'wallet_token' in input_obj:
            # good behavior
            inputs_cleaned.append(input_obj)
        else:
            raise Exception('Invalid Input: %s' % input_obj)

    outputs_cleaned = []
    sweep_funds = False
    for output in outputs:
        assert 'value' in output, output
        assert type(output['value']) is int, output['value']
        if output['value'] == -1:
            sweep_funds = True
            assert not change_address, 'Change Address Supplied for Sweep TX'

        # note that API requires the singleton list 'addresses' which is
        # intentionally hidden away from the user here
        assert 'address' in output, output
        assert is_valid_address_for_coinsymbol(
                b58_address=output['address'],
                coin_symbol=coin_symbol,
                )
        outputs_cleaned.append({
            'value': output['value'],
            'addresses': [output['address'], ],
            })

    if change_address:
        assert is_valid_address_for_coinsymbol(b58_address=change_address,
                coin_symbol=coin_symbol), change_address

    assert preference in ('high', 'medium', 'low', 'zero'), preference

    # Beginning of method code
    url = 'https://api.blockcypher.com/v1/%s/%s/txs/new' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    data = {
            'inputs': inputs_cleaned,
            'outputs': outputs_cleaned,
            'preference': preference,
            }
    if min_confirmations:
        data['confirmations'] = min_confirmations
    if change_address:
        data['change_address'] = change_address

    if include_tosigntx or verify_tosigntx:
        params = {'includeToSignTx': 'true'}  # Nasty hack
    else:
        params = {}

    # Nasty Hack - remove when API updated
    if 'wallet_token' in inputs[0]:
        params['token'] = inputs[0]['wallet_token']
    elif api_key:
        params['token'] = api_key

    r = requests.post(url, data=json.dumps(data), params=params, verify=True, timeout=TIMEOUT_IN_SECONDS)

    unsigned_tx = r.json()

    if verify_tosigntx:
        tx_is_correct, err_msg = verify_unsigned_tx(
                unsigned_tx=unsigned_tx,
                inputs=inputs,
                outputs=outputs,
                sweep_funds=sweep_funds,
                change_address=change_address,
                coin_symbol=coin_symbol,
                )
        if not tx_is_correct:
            print(unsigned_tx)  # for debug
            raise('TX Verification Error: %s' % err_msg)

    return unsigned_tx


def verify_unsigned_tx(unsigned_tx, inputs, outputs, sweep_funds=False,
        change_address=None, coin_symbol='btc'):
    '''
    Takes an unsigned transaction and what was used to build it (in
    create_unsigned_tx) and verifies that tosign_tx matches what is being
    signed and what was requestsed to be signed

    Returns if valid:
        (True, '')
    Returns if invalid:
        (False, 'err_msg')
    '''
    if not change_address and not sweep_funds:
        err_msg = 'Cannot Verify Without Developer Supplying Change Address'
        return False, err_msg

    if 'tosign_tx' not in unsigned_tx:
        err_msg = 'tosign_tx not in API response:\n%s' % unsigned_tx
        return False, err_msg

    output_addr_list = [x['address'] for x in outputs]
    if change_address:
        output_addr_list.append(change_address)

    assert len(unsigned_tx['tosign_tx']) == len(unsigned_tx['tosign']), unsigned_tx
    for cnt, tosign_tx_toverify in enumerate(unsigned_tx['tosign_tx']):

        # Confirm tosign is the dsha256 of tosign_tx
        if double_sha256(tosign_tx_toverify) != unsigned_tx['tosign'][cnt]:
            err_msg = 'double_sha256(%s) =! %s' % (tosign_tx_toverify,
                    unsigned_tx['tosign'][cnt])
            print(unsigned_tx)
            return False, err_msg

        try:
            txn_outputs_response_dict = get_txn_outputs_dict(
                    raw_tx_hex=tosign_tx_toverify,
                    output_addr_list=output_addr_list,
                    coin_symbol=coin_symbol,
                    )
        except Exception as inst:
            # Could be wrong output addresses, keep print statement for debug
            print(unsigned_tx)
            print(coin_symbol)
            return False, str(inst)

        if sweep_funds:
            # output adresses are already confirmed in `get_txn_outputs`,
            # which was called by `get_txn_outputs_dict`
            # no point in confirming values for a sweep
            continue

        else:
            # get rid of change address as tx fee (which affects value)
            # is determined by blockcypher and can't be known up front
            try:
                txn_outputs_response_dict.pop(change_address)
            except KeyError:
                # This is possible in the case of change address not needed
                pass

        user_outputs = compress_txn_outputs(outputs)
        if txn_outputs_response_dict != user_outputs:
            # TODO: more helpful error message
            err_msg = 'API Response Ouputs != Supplied Outputs\n\n%s\n\n%s' % (
                    txn_outputs_response_dict, user_outputs)
            return False, err_msg

    return True, ''


def get_input_addresses(unsigned_tx):
    '''
    Helper function to get the addresses needed used in an unsigned transaction.
    You will next have to retrieve the keys for these addreses in order to sign.

    Depending on how they are generated, unsigned transactions often use
    inputs whose address would be hard to know in advance, hence this step.

    Note: if the same address is used in multiple inputs, it will be returned
    multiple times.
    '''
    addresses = []
    for input_obj in unsigned_tx['tx']['inputs']:
        # TODO: confirm this will work for multisig
        addresses.append(input_obj['addresses'][0])
    return addresses


def make_tx_signatures(txs_to_sign, privkey_list, pubkey_list):
    """
    Loops through txs_to_sign and makes signatures, assumes you already have
    privkey_list and pubkey_list in hexadecimal format.

    Not sure what privkeys and pubkeys to supply?
    Use get_input_addresses to return a list of addresses.
    Matching those addresses to keys is up to you and how you store your
    private keys.

    bitmerchant works well for converting between WIF (or seed)
    and privkey/pubkey hex:
    https://github.com/sbuss/bitmerchant/
    """
    assert len(privkey_list) == len(pubkey_list) == len(txs_to_sign)
    # in the event of multiple inputs using the same pub/privkey,
    # that privkey should be included multiple times

    signatures = []
    for cnt, tx_to_sign in enumerate(txs_to_sign):
        sig = der_encode_sig(*ecdsa_raw_sign(tx_to_sign.rstrip(' \t\r\n\0'),
            privkey_list[cnt]))
        assert ecdsa_raw_verify(tx_to_sign, der_decode_sig(sig),
                pubkey_list[cnt])
        signatures.append(sig)
    return signatures


def broadcast_signed_transaction(unsigned_tx, signatures, pubkeys,
        coin_symbol='btc'):
    '''
    Broadcasts the transaction from create_unsigned_tx
    '''
    assert len(unsigned_tx['tosign']) == len(signatures)
    assert 'errors' not in unsigned_tx

    url = 'https://api.blockcypher.com/v1/%s/%s/txs/send' % (
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_code'],
            COIN_SYMBOL_MAPPINGS[coin_symbol]['blockcypher_network'],
            )
    logger.info(url)

    params = unsigned_tx.copy()
    params['signatures'] = signatures
    params['pubkeys'] = pubkeys

    r = requests.post(url, data=json.dumps(params), verify=True, timeout=TIMEOUT_IN_SECONDS)

    return r.json()
