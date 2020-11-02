import unittest

from blockcypher.utils import is_valid_hash

from blockcypher import simple_spend, simple_spend_p2sh
from blockcypher import get_broadcast_transactions, get_transaction_details
from blockcypher import get_address_details, get_addresses_details
from blockcypher import list_wallet_names
from blockcypher import create_unsigned_tx, create_hd_wallet, derive_hd_address, delete_wallet
from blockcypher import generate_new_address, generate_multisig_address

from blockcypher.utils import is_valid_address, uses_only_hash_chars

import os


BC_API_KEY = os.getenv('BC_API_KEY')
assert BC_API_KEY, 'Blockcypher API KEY Required for Unit Tests'


class TestUtils(unittest.TestCase):

    def setUp(self):
        # first BTC block hash:
        self.valid_hash = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
        self.invalid_hash = 'X'

    def test_valid_hash(self):
        assert is_valid_hash(self.valid_hash), self.valid_hash

    def test_invalid_hash(self):
        assert not is_valid_hash(self.invalid_hash), self.invalid_hash


class GetAddressesDetails(unittest.TestCase):

    def setUp(self):
        pass

    def test_get_addresses_details(self):
        addresses_details = get_addresses_details(
                address_list=[
                    # 2 of the first used BTC addresses
                    '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1',
                    '1FvzCLoTPGANNjWoUo6jUGuAG3wg1w4YjR',
                    ],
                coin_symbol='btc',
                txn_limit=None,
                api_key=BC_API_KEY,
                # This way the test result never changes:
                before_bh=4,
                include_script=True,
                )

        assert len(addresses_details) == 2

        for addr_obj in addresses_details:
            address = addr_obj.get('address')
            if address == '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1':
                assert len(addr_obj['txrefs']) == 1
                assert addr_obj['txrefs'][0]['tx_hash'] == '9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5'
                assert addr_obj['txrefs'][0]['block_height'] == 2
                assert addr_obj['txrefs'][0]['confirmed'] is not None
                assert addr_obj['txrefs'][0]['tx_input_n'] == -1
                assert addr_obj['txrefs'][0]['tx_output_n'] == 0
            elif address == '1FvzCLoTPGANNjWoUo6jUGuAG3wg1w4YjR':
                assert len(addresses_details[1]['txrefs']) == 1
                assert addr_obj['txrefs'][0]['tx_hash'] == '999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644'
                assert addr_obj['txrefs'][0]['block_height'] == 3
                assert addr_obj['txrefs'][0]['confirmed'] is not None
                assert addr_obj['txrefs'][0]['tx_input_n'] == -1
                assert addr_obj['txrefs'][0]['tx_output_n'] == 0
            else:
                assert False, 'Invalid address: %s' % address
            for txref in addr_obj['txrefs']:
                assert 'script' in txref, txref


class CreateUnsignedTX(unittest.TestCase):

    def setUp(self):
        pass

    def test_create_basic_unsigned(self):
        # This address I previously sent funds to but threw out the private key
        result = create_unsigned_tx(
                inputs=[
                    {'address': 'BwvSPyMWVL1gkp5FZdrGXLpHj2ZJyJYLVB'},
                    ],
                outputs=[
                    {
                        'value': -1,
                        # p2sh address for extra measure
                        'address': 'Dbc9fnf1Kqct7zvfNTiwr6HjvDfPYaFSNg',
                        },
                    ],
                change_address=None,
                include_tosigntx=True,
                # will test signature returned locally:
                verify_tosigntx=True,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )
        self.assertNotIn('errors', result)

    def test_create_ps2h_unsigned(self):
        # This address I previously sent funds to but threw out the private key
        result = create_unsigned_tx(
                inputs=[
                    {
                        'pubkeys': [
                            '036f5ca449944655b5c580ff6686bdd19123d1003b41f49f4b603f53e33f70a2d1',
                            '03e93a754aa03dedbe032e5be051bce031db4337c48fbbcf970d1b27bb25a07964',
                            '02582061ab1dba9d6b5b4e6e29f9da2bd590862f1b1e8566f405eb1d92898eafee',
                            ],
                        'script_type': 'multisig-2-of-3'
                        },
                    ],
                outputs=[
                    {
                        'value': -1,
                        'address': 'CFr99841LyMkyX5ZTGepY58rjXJhyNGXHf',
                        },
                    ],
                change_address=None,
                include_tosigntx=True,
                # will test signature returned locally:
                verify_tosigntx=True,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )
        self.assertNotIn('errors', result)

    def test_create_nulldata_unsigned(self):
        # This address I previously sent funds to but threw out the private key
        result = create_unsigned_tx(
                inputs=[
                    {'address': 'BwvSPyMWVL1gkp5FZdrGXLpHj2ZJyJYLVB'},
                    ],
                outputs=[
                    # embed some null-data
                    {
                        'value': 0,
                        'script_type': 'null-data',
                        'script': '6a06010203040506',
                        },
                    ],
                change_address='CFr99841LyMkyX5ZTGepY58rjXJhyNGXHf',
                include_tosigntx=True,
                # will test signature returned locally:
                verify_tosigntx=True,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )
        self.assertNotIn('errors', result)

    def test_create_from_inputs(self):
        result = create_unsigned_tx(
            inputs=[
                {
                    'prev_hash': 'b56c936ec5512e03761b3ef7614d00fa54d6931abe6903efa6f8792dc3305a69',
                    'output_index': 0
                },
                {
                    'prev_hash': 'fe313e2c309b4f256157ec4ebcf55652eaedb8a16d429df26c5ba205dd40ad27',
                    'output_index': 0
                },
                {
                    'prev_hash': '12f30c25afafcb42171e7052c9596c93a3e81b0d2b9051f8cf25ce44693e24ba',
                    'output_index': 0
                },
                {
                    'prev_hash': '0affbdc61b86a05944ce0bc167be60106925d631abb38258c5cdc1764002796d',
                    'output_index': 0
                },
                {
                    'prev_hash': '31746be47c39337b8c054a165da407122725162363e5b9d0b8062cde3ef06f7d',
                    'output_index': 0
                }
            ],
            outputs=[
                {
                    'value': 1,
                    'address': 'Dbc9fnf1Kqct7zvfNTiwr6HjvDfPYaFSNg',
                },
            ],
            preference="low",
            change_address='CFr99841LyMkyX5ZTGepY58rjXJhyNGXHf',
            include_tosigntx=True,
            verify_tosigntx=True,
            coin_symbol='bcy',
            api_key=BC_API_KEY,
        )
        self.assertNotIn('errors', result)


class GetAddressDetails(unittest.TestCase):

    def test_fetching_unspents(self):
        # This address I previously sent funds to but threw out the private key
        address_details = get_address_details(
                address='C3B3dU12vpCVh2jfmGFdqLe5KWxtZfXW8j',
                coin_symbol='bcy',
                txn_limit=None,
                api_key=BC_API_KEY,
                unspent_only=True,
                show_confidence=False,  # don't return confidence info
                # This way the test result never changes:
                before_bh=592822,
                include_script=True,
                )
        assert len(address_details['txrefs']) == 1
        assert address_details['txrefs'][0]['tx_hash'] == 'b12c4b0ab466c9bbd05da88b3be1a13229c85a6edd2869e01e6a557c8a5cca2b'
        assert address_details['txrefs'][0]['block_height'] == 592821
        assert address_details['txrefs'][0]['tx_input_n'] == -1
        assert address_details['txrefs'][0]['tx_output_n'] == 0
        assert address_details['txrefs'][0]['value'] == 1000000
        assert address_details['txrefs'][0]['spent'] is False
        assert address_details['txrefs'][0]['double_spend'] is False
        assert address_details['txrefs'][0]['confirmed'] is not None
        for txref in address_details['txrefs']:
            assert 'script' in txref, txref

    def test_get_address_details_before(self):
        address_details = get_address_details(
                address='1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1',
                coin_symbol='btc',
                txn_limit=None,
                api_key=BC_API_KEY,
                show_confidence=False,  # don't return confidence info
                # This way the test result never changes:
                before_bh=4,
                )

        # first TX
        assert len(address_details['txrefs']) == 1
        assert address_details['txrefs'][0]['tx_hash'] == '9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5'
        assert address_details['txrefs'][0]['block_height'] == 2
        assert address_details['txrefs'][0]['confirmed'] is not None
        assert address_details['txrefs'][0]['tx_input_n'] == -1
        assert address_details['txrefs'][0]['tx_output_n'] == 0

    def test_get_address_details_after(self):
        address_details = get_address_details(
                address='1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1',
                coin_symbol='btc',
                api_key=BC_API_KEY,
                show_confidence=False,  # don't return confidence info
                # Exclude first result
                after_bh=4,
                txn_limit=1,
                )

        assert len(address_details['txrefs']) == 1
        assert address_details['txrefs'][0]['tx_hash'] != '9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5'
        assert address_details['txrefs'][0]['block_height'] != 2


class GetUnconfirmedTXInfo(unittest.TestCase):

    def test_unconfirmed_tx_confidence(self):
        # fetch a recent tx hash (assume BTC will always have an unconfirmed TX):
        recent_tx_hash = get_broadcast_transactions(
                coin_symbol='btc',
                api_key=BC_API_KEY,
                limit=1,
                )[0]['hash']
        # get confidence info for it
        tx_details = get_transaction_details(
                tx_hash=recent_tx_hash,
                coin_symbol='btc',
                limit=1,
                tx_input_offset=None,
                tx_output_offset=None,
                include_hex=False,
                confidence_only=True,
                api_key=BC_API_KEY,
                )

        assert 'receive_count' in tx_details, tx_details
        assert 'preference' in tx_details, tx_details
        assert 'age_millis' in tx_details, tx_details
        assert 'confidence' in tx_details, tx_details
        assert 0 <= tx_details['confidence'] <= 1, tx_details


class CompressedTXSign(unittest.TestCase):

    def setUp(self):
        self.bcy_faucet_addr = 'CFr99841LyMkyX5ZTGepY58rjXJhyNGXHf'
        self.to_send_satoshis = 1

        # Note: this is BCY testnet coin, which is completely worthless and available here for free:
        # https://accounts.blockcypher.com/blockcypher-faucet
        self.bcy_pub_addr = 'CCf3dWFULG2JHyYjmLixBSWGxF9YwTGaae'
        self.bcy_privkey_hex = '2e376712b1574d4465ce08c0299ebac0f8ee4e1b90c143543c446b13ea31d1d5'
        self.bcy_privkey_wif = 'BpssP5kLsnygEaHuodnpQBChvi2YszWGAgstUfDmXTX3Y4EG3pv4'
        self.bcy_pubkey_hex = '2e376712b1574d4465ce08c0299ebac0f8ee4e1b90c143543c446b13ea31d1d5'  # not actually used

        # Generation steps:
        # $ curl -X POST https://api.blockcypher.com/v1/bcy/test/addrs

    def test_simple_spend_hex(self):
        tx_hash = simple_spend(
                from_privkey=self.bcy_privkey_hex,
                to_address=self.bcy_faucet_addr,
                to_satoshis=self.to_send_satoshis,
                privkey_is_compressed=True,
                api_key=BC_API_KEY,
                coin_symbol='bcy',
                )
        # confirm details (esp that change sent back to sender address)
        tx_details = get_transaction_details(
                tx_hash=tx_hash,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )

        for input_obj in tx_details['inputs']:
            assert len(input_obj['addresses']) == 1, input_obj['addresses']
            assert input_obj['addresses'][0] == self.bcy_pub_addr
            assert input_obj['script_type'] == 'pay-to-pubkey-hash'

        for output_obj in tx_details['outputs']:
            assert len(output_obj['addresses']) == 1, input_obj['addresses']
            assert output_obj['script_type'] == 'pay-to-pubkey-hash'

            if output_obj['addresses'][0] == self.bcy_pub_addr:
                # this is change
                output_obj['value'] > 0
            elif output_obj['addresses'][0] == self.bcy_faucet_addr:
                # this is the tx
                output_obj['value'] == self.to_send_satoshis
            else:
                raise Exception('Invalid Output Address: %s' % output_obj['addresses'][0])

    def test_simple_spend_wif(self):
        tx_hash = simple_spend(
                from_privkey=self.bcy_privkey_wif,
                to_address=self.bcy_faucet_addr,
                to_satoshis=self.to_send_satoshis,
                privkey_is_compressed=True,
                api_key=BC_API_KEY,
                coin_symbol='bcy',
                )
        # confirm details (esp that change sent back to sender address)
        tx_details = get_transaction_details(
                tx_hash=tx_hash,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )

        for input_obj in tx_details['inputs']:
            assert len(input_obj['addresses']) == 1, input_obj['addresses']
            assert input_obj['addresses'][0] == self.bcy_pub_addr
            assert input_obj['script_type'] == 'pay-to-pubkey-hash'

        for output_obj in tx_details['outputs']:
            assert len(output_obj['addresses']) == 1, input_obj['addresses']
            assert output_obj['script_type'] == 'pay-to-pubkey-hash'

            if output_obj['addresses'][0] == self.bcy_pub_addr:
                # this is change
                output_obj['value'] > 0
            elif output_obj['addresses'][0] == self.bcy_faucet_addr:
                # this is the tx
                output_obj['value'] == self.to_send_satoshis
            else:
                raise Exception('Invalid Output Address: %s' % output_obj['addresses'][0])

    def test_simple_spend_p2sh(self):
        from_addr = 'Dpuo6iMtoZW3oNsNuALHTEyyw55fBMxiqE'
        # keys that went into building from_addr
        all_from_pubkeys = [
                '022d1d33c917e0c1ca677b8c6d47ee55b59880630afe8290517fc7de640ce257f5',
                '038a5f1bd7eeb34f53a014f81bfd50869cf6d972ee2bef078f6b67d4c8dd9432b2',
                '033796355300f6a50602f701fcf06baebf8b160553e100852703a9363522227a53',
                ]
        # 2 of 3 of the corresponding keys above
        from_privkeys_to_use = [
                '57067d2852b5f92d18d82a09c2b658184eb85a38fe47adb8db85203a42f91e8f',
                'c4bbc144bc5351288aa46c694a32eceaff739945510cca8bdd924d1c660ff1f4'
                ]

        tx_hash = simple_spend_p2sh(
                all_from_pubkeys=all_from_pubkeys,
                from_privkeys_to_use=from_privkeys_to_use,
                to_address=self.bcy_faucet_addr,
                to_satoshis=1,
                # change addr must be explicit:
                change_address=from_addr,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )

        # confirm details (esp that change sent back to sender address)
        tx_details = get_transaction_details(
                tx_hash=tx_hash,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )

        for input_obj in tx_details['inputs']:
            assert len(input_obj['addresses']) == 1, input_obj['addresses']
            assert input_obj['addresses'][0] == from_addr
            assert input_obj['script_type'] == 'pay-to-script-hash'

        for output_obj in tx_details['outputs']:
            assert len(output_obj['addresses']) == 1, input_obj['addresses']

            if output_obj['addresses'][0] == from_addr:
                # this is change
                assert output_obj['script_type'] == 'pay-to-script-hash'
                output_obj['value'] > 0
            elif output_obj['addresses'][0] == self.bcy_faucet_addr:
                # this is the tx
                assert output_obj['script_type'] == 'pay-to-pubkey-hash'
                output_obj['value'] == 1
            else:
                raise Exception('Invalid Output Address: %s' % output_obj['addresses'][0])


class UncompressedTXSign(unittest.TestCase):

    def setUp(self):
        self.bcy_faucet_addr = 'CFr99841LyMkyX5ZTGepY58rjXJhyNGXHf'
        self.to_send_satoshis = 1

        # Note: this is BCY testnet coin, which is completely worthless and available here for free:
        # https://accounts.blockcypher.com/blockcypher-faucet
        self.bcy_pub_addr = 'BtbkHeUzCs7ByHgZnX9UmSsqpD9uZcADXB'
        self.bcy_privkey_hex = '669c1078565cc25a358dfc291437e10553dbfefe128a18cb48dfe0bd0774d86e'
        self.bcy_privkey_wif = '3TgXuPViKviQ1aKd6yVRmyD6oSVougJgagPbAbb7VykAVwYD3PQ'
        self.bcy_pubkey_hex = '0484a07ce10c2f562ff9af96442dfff41f1f608c215583802562b3b0b4a73892740d729682eefd329dbf3a92580638e98aaa738bc05ee08605f29d99987f0c4d4a'  # not actually used

        # generation steps:
        '''
        from bitmerchant.wallet import Wallet
        from bitmerchant.network import BlockCypherTestNet

        wallet = Wallet.new_random_wallet(network=BlockCypherTestNet)
        wallet.private_key.get_key()
        wallet.private_key.export_to_wif(compressed=False)
        wallet.public_key.get_key(compressed=False)
        wallet.public_key.to_address(compressed=False)
        '''

    def test_simple_spend_hex(self):
        tx_hash = simple_spend(
                from_privkey=self.bcy_privkey_hex,
                to_address=self.bcy_faucet_addr,
                to_satoshis=self.to_send_satoshis,
                privkey_is_compressed=False,
                api_key=BC_API_KEY,
                coin_symbol='bcy',
                )
        # confirm details (esp that change sent back to sender address)
        tx_details = get_transaction_details(
                tx_hash=tx_hash,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )

        for input_obj in tx_details['inputs']:
            assert len(input_obj['addresses']) == 1, input_obj['addresses']
            assert input_obj['addresses'][0] == self.bcy_pub_addr
            assert input_obj['script_type'] == 'pay-to-pubkey-hash'

        for output_obj in tx_details['outputs']:
            assert len(output_obj['addresses']) == 1, input_obj['addresses']
            assert output_obj['script_type'] == 'pay-to-pubkey-hash'

            if output_obj['addresses'][0] == self.bcy_pub_addr:
                # this is change
                output_obj['value'] > 0
            elif output_obj['addresses'][0] == self.bcy_faucet_addr:
                # this is the tx
                output_obj['value'] == self.to_send_satoshis
            else:
                raise Exception('Invalid Output Address: %s' % output_obj['addresses'][0])

    def test_simple_spend_wif(self):
        tx_hash = simple_spend(
                from_privkey=self.bcy_privkey_wif,
                to_address=self.bcy_faucet_addr,
                to_satoshis=self.to_send_satoshis,
                privkey_is_compressed=False,
                api_key=BC_API_KEY,
                coin_symbol='bcy',
                )
        # confirm details (esp that change sent back to sender address)
        tx_details = get_transaction_details(
                tx_hash=tx_hash,
                coin_symbol='bcy',
                api_key=BC_API_KEY,
                )

        for input_obj in tx_details['inputs']:
            assert len(input_obj['addresses']) == 1, input_obj['addresses']
            assert input_obj['addresses'][0] == self.bcy_pub_addr
            assert input_obj['script_type'] == 'pay-to-pubkey-hash'

        for output_obj in tx_details['outputs']:
            assert len(output_obj['addresses']) == 1, input_obj['addresses']
            assert output_obj['script_type'] == 'pay-to-pubkey-hash'

            if output_obj['addresses'][0] == self.bcy_pub_addr:
                # this is change
                output_obj['value'] > 0
            elif output_obj['addresses'][0] == self.bcy_faucet_addr:
                # this is the tx
                output_obj['value'] == self.to_send_satoshis
            else:
                raise Exception('Invalid Output Address: %s' % output_obj['addresses'][0])


class GenerateAddressServerSide(unittest.TestCase):

    def test_generate_single_addr(self):
        for coin_symbol in ('btc', 'btc-testnet', 'doge', 'dash', 'ltc', 'bcy'):
            response_dict = generate_new_address(
                    coin_symbol=coin_symbol,
                    api_key=BC_API_KEY,
                    )
            assert is_valid_address(response_dict['address']), response_dict
            assert uses_only_hash_chars(response_dict['private']), response_dict
            assert uses_only_hash_chars(response_dict['public']), response_dict
            assert 'wif' in response_dict, response_dict

    def test_generate_multisig_addr(self):
        # http://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/
        response_dict = generate_multisig_address(
                pubkey_list=[
                    '04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd',
                    '046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187',
                    '0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83'
                    ],
                script_type='multisig-2-of-3',
                coin_symbol='btc',
                api_key=BC_API_KEY,
                )
        assert response_dict['address'] == '347N1Thc213QqfYCz3PZkjoJpNv5b14kBd', response_dict


class RegisterHDWallet(unittest.TestCase):
    def test_register_btc_wallet(self):
        result = create_hd_wallet(
            "blockcypher-testsuite-btc",
            "xpub661MyMwAqRbcGHGJXmM5jX85xJtNmjLgyzs7LpCwBnpfK8SF7TktReXmEt2NzuDhi4NCRanpCRynoewDE6Psuptz7gDW1Uxbfsf56GEfmgo",
            coin_symbol='btc',
            api_key=BC_API_KEY
        )
        wallets = list_wallet_names(api_key=BC_API_KEY)['wallet_names']
        self.assertIn('blockcypher-testsuite-btc', wallets)
        derivation_response = derive_hd_address(
            api_key=BC_API_KEY,
            wallet_name="blockcypher-testsuite-btc",
            num_addresses=1,
            subchain_index=0,
            coin_symbol="btc",
        )
        list_addresses = ["14a2zs9YhAxEo3xworxiJML47STab1LZMe", "18ZNuW7HEdMrM7ASfDESN7r5mTBHPPEjyo"]
        self.assertIn(derivation_response['chains'][0]['chain_addresses'][0]['address'], list_addresses)

        delete_wallet(
            'blockcypher-testsuite-btc',
            coin_symbol='btc',
            api_key=BC_API_KEY,
            is_hd_wallet=True)


if __name__ == '__main__':
    unittest.main(failfast=True)
