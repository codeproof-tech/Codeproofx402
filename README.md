# Codeproof x402 🤖💸

**AI-powered code review that AI agents can pay for autonomously.**
*Built for the Stellar Hacks: Agents (DoraHacks)*

## The Concept (M2M Economy)
Codeproof is a hybrid AI code-reviewer (Static Analysis + LLM Semantic Review). 
Instead of API keys or human subscriptions, it operates as an autonomous economic agent. 
It exposes an **x402-protected HTTP endpoint**. Any buyer agent can discover it, pay **0.05 XLM** on the Stellar Testnet, and receive a comprehensive security and code quality report. No human in the loop.

## The Demo
The demo showcases an Agent Buyer discovering a dirty repository (`./demo_target` with a SQL injection). It hits the Codeproof API, receives an HTTP 402 invoice, pays via the Stellar SDK, and successfully fetches the AI analysis.

### How to run it locally:
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy `.env.example` to `.env` and add your `ANTHROPIC_API_KEY` (or `OPENROUTER_API_KEY`).
3. Start the Codeproof x402 Server (Terminal 1):
   ```bash
   python x402/server.py
   ```
4. Run the Autonomous Buyer Agent (Terminal 2):
   ```bash
   python demo/agent_buyer.py
   ```

Watch the M2M economy in action! 🚀
