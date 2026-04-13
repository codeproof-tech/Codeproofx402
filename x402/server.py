import sys
import os
from dotenv import load_dotenv
load_dotenv()

import uuid
from pathlib import Path
from flask import Flask, request, jsonify
from stellar_verifier import verify_payment

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeproof import run_verify_pipeline
from codeproof.diff_reviewer import review_diff_multi, DEFAULT_MODELS
from codeproof.llm_client import LLMClient
from codeproof.pr_coach import enrich_findings

app = Flask(__name__)

MY_STELLAR_WALLET = "GBRIAVFD6KODHY4BROBXRMCHQRX6BDUBMSJNEVEYSRVZTG3NLCHDPDEG"
PRICE_XLM = "0.05"

@app.route('/review', methods=['POST'])
def review_code():
    data = request.json or {}
    repo_path = data.get('repo_dir')
    
    if not repo_path:
        return jsonify({"error": "repo_dir is required"}), 400

    payment_hash = request.headers.get('X-Payment-Hash')
    request_id = request.headers.get('X-Request-Id', str(uuid.uuid4().hex[:8]))

    if not payment_hash:
        return jsonify({
            "error": "Payment Required",
            "price": PRICE_XLM,
            "currency": "XLM",
            "network": "stellar-testnet",
            "recipient": MY_STELLAR_WALLET,
            "memo": request_id,
            "message": "Pay 0.05 XLM to the recipient with the memo to access this API. Include tx hash in X-Payment-Hash header."
        }), 402

    if not verify_payment(payment_hash, request_id, MY_STELLAR_WALLET):
        return jsonify({"error": "Invalid or unverified payment hash"}), 403

    try:
        print(f"[Server] Running static pipeline for {repo_path}...")
        result = run_verify_pipeline(repo_dir=repo_path)
        
        print("[Server] Sending code to LLMs for semantic review...")
        pseudo_diff = ""
        for file in Path(repo_path).rglob("*.py"):
            if ".venv" in file.parts or "__pycache__" in file.parts:
                continue
            try:
                content = file.read_text(encoding="utf-8")
                pseudo_diff += f"\n--- a/{file.name}\n+++ b/{file.name}\n@@ -1,1 +1,1 @@\n{content}\n"
            except Exception:
                pass

        if pseudo_diff:
            findings = review_diff_multi(pseudo_diff[:8000], LLMClient(), DEFAULT_MODELS[:2])
            result.findings = enrich_findings(findings)
            result.models_used = DEFAULT_MODELS[:2]

        return jsonify({
            "status": "success",
            "verdict": result.verdict,
            "fitness": result.fitness,
            "report": result.to_markdown()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=8080)