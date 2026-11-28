"""Check from the command line whether a vault fingerprint is anchored on-chain (no wallet needed).

    SEPOLIA_RPC_URL=... SHESHIELD_CONTRACT_ADDRESS=0x... python scripts/verify_anchor.py <64-hex fingerprint>
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64:
        sys.exit("usage: verify_anchor.py <64-hex-char fingerprint>")
    rpc, addr = os.environ.get("SEPOLIA_RPC_URL"), os.environ.get("SHESHIELD_CONTRACT_ADDRESS")
    if not rpc or not addr:
        sys.exit("Set SEPOLIA_RPC_URL and SHESHIELD_CONTRACT_ADDRESS.")
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(rpc))
    abi = json.load(open(os.path.join(HERE, "..", "contracts", "SheShieldAnchor.abi.json")))
    exists, who, ts, blk = w3.eth.contract(address=Web3.to_checksum_address(addr), abi=abi).functions.getAnchor(bytes.fromhex(sys.argv[1])).call()
    print("anchored:", exists)
    if exists:
        print("by:", who, "block:", blk, "timestamp:", ts)


if __name__ == "__main__":
    main()
