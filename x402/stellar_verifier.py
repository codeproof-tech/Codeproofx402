from stellar_sdk import Server
from stellar_sdk.exceptions import NotFoundError
import logging

log = logging.getLogger(__name__)

HORIZON_URL = "https://horizon-testnet.stellar.org"
EXPECTED_AMOUNT = "0.0500000"
EXPECTED_ASSET_CODE = "XLM"

def verify_payment(tx_hash: str, expected_memo: str, receiver_wallet: str) -> bool:
    """Verifies a transaction in the Stellar Testnet."""
    server = Server(horizon_url=HORIZON_URL)
    
    try:
        tx = server.transactions().transaction(tx_hash).call()
        
        if tx.get("memo") != expected_memo:
            log.warning(f"Memo mismatch. Expected {expected_memo}, got {tx.get('memo')}")
            return False
            
        operations = server.operations().for_transaction(tx_hash).call()
        for op in operations['_embedded']['records']:
            if op['type'] == 'payment' and op['to'] == receiver_wallet:
                if op['amount'] == EXPECTED_AMOUNT:
                    return True
                    
        log.warning("Transaction found, but no matching payment operation.")
        return False
        
    except NotFoundError:
        log.warning(f"Transaction {tx_hash} not found in Stellar testnet.")
        return False
    except Exception as e:
        log.error(f"Error verifying transaction: {e}")
        return False