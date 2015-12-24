import unittest

from blockcypher.utils import is_valid_hash

from blockcypher import simple_spend
from blockcypher import get_transaction_details
from blockcypher import get_address_details, get_addresses_details

import os


BC_API_KEY = os.getenv('BC_API_KEY')


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


class GetAddressDetails(unittest.TestCase):

    def test_get_address_details_before(self):
        address_details = get_address_details(
                address='1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1',
                coin_symbol='btc',
                txn_limit=None,
                api_key=BC_API_KEY,
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
                # Exclude first result
                after_bh=4,
                txn_limit=1,
                )

        assert len(address_details['txrefs']) == 1
        assert address_details['txrefs'][0]['tx_hash'] != '9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5'
        assert address_details['txrefs'][0]['block_height'] != 2


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
        tx_details = get_transaction_details(tx_hash=tx_hash, coin_symbol='bcy')

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
        tx_details = get_transaction_details(tx_hash=tx_hash, coin_symbol='bcy')

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
        tx_details = get_transaction_details(tx_hash=tx_hash, coin_symbol='bcy')

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
        tx_details = get_transaction_details(tx_hash=tx_hash, coin_symbol='bcy')

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


if __name__ == '__main__':
    unittest.main(failfast=True)
