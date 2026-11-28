import json, os, pytest
web3 = pytest.importorskip("web3")
from web3 import Web3, EthereumTesterProvider

C = os.path.join(os.path.dirname(__file__), "..", "contracts")


@pytest.fixture()
def ctr():
    w3 = Web3(EthereumTesterProvider())
    with open(os.path.join(C, "SheShieldAnchor.abi.json")) as f:
        abi = json.load(f)
    with open(os.path.join(C, "SheShieldAnchor.bin")) as f:
        code = "0x" + f.read().strip()
    tx = w3.eth.contract(abi=abi, bytecode=code).constructor().transact({"from": w3.eth.accounts[0]})
    addr = w3.eth.wait_for_transaction_receipt(tx).contractAddress
    return w3, w3.eth.contract(address=addr, abi=abi)


def fp(n):
    return bytes.fromhex(f"{n:064x}")


def test_anchor_and_read_back(ctr):
    w3, c = ctr
    assert c.functions.getAnchor(fp(1)).call()[0] is False
    c.functions.anchor(fp(1)).transact({"from": w3.eth.accounts[1]})
    ex, who, ts, blk = c.functions.getAnchor(fp(1)).call()
    assert ex and who == w3.eth.accounts[1] and ts > 0 and blk > 0
    assert c.functions.latestOf(w3.eth.accounts[1]).call() == fp(1)


def test_unknown_fingerprint_not_found(ctr):
    _, c = ctr
    assert c.functions.getAnchor(fp(99)).call()[0] is False


def test_duplicate_and_empty_rejected(ctr):
    w3, c = ctr
    c.functions.anchor(fp(2)).transact({"from": w3.eth.accounts[0]})
    with pytest.raises(Exception):
        c.functions.anchor(fp(2)).transact({"from": w3.eth.accounts[0]})
    with pytest.raises(Exception):
        c.functions.anchor(b"\x00" * 32).transact({"from": w3.eth.accounts[0]})


def test_first_anchorer_cannot_be_overwritten(ctr):
    w3, c = ctr
    c.functions.anchor(fp(3)).transact({"from": w3.eth.accounts[1]})
    with pytest.raises(Exception):
        c.functions.anchor(fp(3)).transact({"from": w3.eth.accounts[2]})
    assert c.functions.getAnchor(fp(3)).call()[1] == w3.eth.accounts[1]
