import requests
import time
import sys
from stellar_sdk import Server, Keypair, TransactionBuilder, Network

CODEPROOF_API = "http://127.0.0.1:8080/review"
TARGET_REPO = "./demo_target"

BUYER_SECRET = "SCCSIMNSVZWVVNZENEGNSAAANHJLETJJBSQXME2YBZE7IICRLSFT6FKV" 

def pay_invoice(invoice: dict) -> str:
    print("\n[Agent Buyer] 💸 Received HTTP 402 Payment Required.")
    print(f"[Agent Buyer] Invoice details: {invoice['price']} {invoice['currency']} to {invoice['recipient']}")
    print(f"[Agent Buyer] Memo ID: {invoice['memo']}")
    print("[Agent Buyer] Initiating Stellar Testnet transaction...")

    server = Server("https://horizon-testnet.stellar.org")
    buyer_keypair = Keypair.from_secret(BUYER_SECRET)
    
    try:
        buyer_account = server.load_account(buyer_keypair.public_key)
    except Exception:
        print("[!] Error: Buyer account not funded. Use Stellar Friendbot to fund it first.")
        sys.exit(1)

    transaction = (
        TransactionBuilder(
            source_account=buyer_account,
            network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
            base_fee=100
        )
        .append_payment_op(
            destination=invoice["recipient"],
            asset_code="XLM",
            amount=invoice["price"]
        )
        .add_text_memo(invoice["memo"])
        .set_timeout(30)
        .build()
    )

    transaction.sign(buyer_keypair)
    response = server.submit_transaction(transaction)
    tx_hash = response["hash"]
    
    print("[Agent Buyer] ✅ Payment successful!")
    print(f"[Agent Buyer] 🔗 Stellar Explorer: https://stellar.expert/explorer/testnet/tx/{tx_hash}")
    return tx_hash


def main():
    print("[Agent Buyer] 🤖 Requesting Code Review for repository...")
    
    response = requests.post(CODEPROOF_API, json={"repo_dir": TARGET_REPO})
    
    if response.status_code == 402:
        invoice = response.json()
        
        tx_hash = pay_invoice(invoice)
        
        print("\n[Agent Buyer] 🔄 Retrying request with X-Payment-Hash header...")
        time.sleep(2)
        
        headers = {"X-Payment-Hash": tx_hash}
        final_response = requests.post(CODEPROOF_API, json={"repo_dir": TARGET_REPO}, headers=headers)
        
        if final_response.status_code == 200:
            data = final_response.json()
            print("\n[Agent Buyer] 🎉 Success! Review received.")
            print(f"Verdict: {data['verdict']} | Fitness: {data['fitness']}")
            print("\n--- Review Report ---")
            print(data['report'][:500] + "...\n[Report Truncated for Demo]")
        else:
            print(f"[!] Error: {final_response.status_code} - {final_response.text}")
            
    else:
        print(f"[!] Unexpected response: {response.status_code} - {response.text}")

if __name__ == "__main__":
    main()