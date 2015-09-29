# Not DRY, but best compromise for removing the learning curve for the library
"""
With this you can write code like the following:
>>> import blockcypher
>>> blockcypher.get_latest_block_height()
"""

# Main methods used
from .api import get_address_details
from .api import get_addresses_details
from .api import get_transaction_details
from .api import get_transactions_details
from .api import get_block_overview
from .api import get_blocks_overview
from .api import get_block_details
from .api import get_blockchain_overview
from .api import get_blockchain_fee_estimates
from .api import get_blockchain_high_fee
from .api import get_blockchain_medium_fee
from .api import get_blockchain_low_fee
from .api import get_latest_block_height
from .api import get_latest_block_hash
from .api import get_total_balance
from .api import get_unconfirmed_balance
from .api import get_confirmed_balance
from .api import get_num_confirmed_transactions
from .api import get_num_unconfirmed_transactions
from .api import get_total_num_transactions
from .api import generate_new_address
from .api import derive_hd_address
from .api import get_num_confirmations
from .api import get_confidence
from .api import get_miner_preference
from .api import get_receive_count
from .api import get_satoshis_transacted
from .api import get_satoshis_in_fees
from .api import get_merkle_root
from .api import get_bits
from .api import get_nonce
from .api import get_prev_block_hash
from .api import get_block_hash
from .api import get_block_height
from .api import get_broadcast_transactions
from .api import get_broadcast_transaction_hashes
from .api import subscribe_to_address_webhook
from .api import pushtx
from .api import decodetx
from .api import get_forwarding_address
from .api import get_forwarding_address_details
from .api import list_forwarding_addresses
from .api import delete_forwarding_address
from .api import send_faucet_coins
from .api import create_wallet_from_address
from .api import create_hd_wallet
from .api import get_wallet_addresses
from .api import get_wallet_balance
from .api import get_wallet_transactions
from .api import get_latest_paths_from_hd_wallet_addresses
from .api import add_address_to_wallet
from .api import remove_address_from_wallet
from .api import delete_wallet
from .api import create_unsigned_tx
from .api import verify_unsigned_tx
from .api import get_input_addresses
from .api import make_tx_signatures
from .api import broadcast_signed_transaction

from .utils import from_satoshis
from .utils import satoshis_to_btc
from .utils import is_valid_hash
from .utils import is_valid_address
