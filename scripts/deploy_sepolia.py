"""Deploy SheShieldAnchor to Sepolia. Secrets come from environment variables only.

    SEPOLIA_RPC_URL        https RPC endpoint (Alchemy, Infura, public node, ...)
    DEPLOYER_PRIVATE_KEY   private key of a TEST wallet holding Sepolia ETH. Never use a wallet with real funds.

    python scripts/deploy_sepolia.py

Prints the contract address. Then set SHESHIELD_CONTRACT_ADDRESS to it and restart the app.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
C = os.path.join(HERE, "..", "contracts")


def main():
    rpc, key = os.environ.get("SEPOLIA_RPC_URL"), os.environ.get("DEPLOYER_PRIVATE_KEY")
    if not rpc or not key:
        sys.exit("Set SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY (a test wallet) in your environment. Nothing was sent.")
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        sys.exit("Could not connect to the RPC endpoint.")
    if w3.eth.chain_id != 11155111:
        sys.exit(f"Refusing to deploy: chain id is {w3.eth.chain_id}, expected 11155111 (Sepolia).")
    acct = w3.eth.account.from_key(key)
    bal = w3.eth.get_balance(acct.address)
    print("Deployer:", acct.address, "balance:", w3.from_wei(bal, "ether"), "ETH")
    if bal == 0:
        sys.exit("This wallet has no Sepolia ETH. Get test ETH from a Sepolia faucet.")
    abi = json.load(open(os.path.join(C, "SheShieldAnchor.abi.json")))
    bytecode = "0x" + open(os.path.join(C, "SheShieldAnchor.bin")).read().strip()
    ctr = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = ctr.constructor().build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address),
                                              "chainId": 11155111})
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    print("Deployment tx:", h.hex(), "- waiting for confirmation...")
    r = w3.eth.wait_for_transaction_receipt(h, timeout=300)
    if r.status != 1:
        sys.exit("Deployment failed.")
    print("\nContract deployed at:", r.contractAddress)
    print("Etherscan: https://sepolia.etherscan.io/address/" + r.contractAddress)
    print("\nNext: set SHESHIELD_CONTRACT_ADDRESS=" + r.contractAddress)
    with open(os.path.join(C, "deployment.sepolia.json"), "w") as f:
        json.dump({"network": "sepolia", "chainId": 11155111, "address": r.contractAddress,
                   "deployTx": h.hex(), "block": r.blockNumber}, f, indent=2)


if __name__ == "__main__":
    main()
