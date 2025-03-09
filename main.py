import json
import os
from decimal import Decimal
import msgpack
from eth_utils.crypto import keccak
from eth_utils.conversions import to_hex

from hyperliquid.utils import constants
from hyperliquid.utils.signing import MULTI_SIG_ENVELOPE_SIGN_TYPES, construct_phantom_agent, get_timestamp_ms
from hyperliquid.info import Info
from hyperliquid.exchange import Exchange


def float_to_wire(x: float) -> str:
    """Convert float to wire format string."""
    rounded = f"{x:.8f}"
    if rounded == "-0":
        rounded = "0"
    normalized = Decimal(rounded).normalize()
    return f"{normalized:f}"


def address_to_bytes(address):
    """Convert an Ethereum address to bytes."""
    return bytes.fromhex(address[2:] if address.startswith("0x") else address)


def action_hash(action, vault_address, nonce):
    """Generate action hash for signing."""
    data = msgpack.packb(action)
    data += nonce.to_bytes(8, "big")
    if vault_address is None:
        data += b"\x00"
    else:
        data += b"\x01"
        data += address_to_bytes(vault_address)
    return keccak(data)


def order_type_to_wire(order_type):
    """Convert order type to wire format."""
    if order_type == "limit":
        return {"limit": {"tif": "Gtc"}}
    elif order_type == "market":
        return {"limit": {"tif": "Ioc"}}
    else:
        raise ValueError("Unsupported order type")


def create_order_action(coin_name, coin_index, is_buy, size, price, order_type):
    """Create an order action for signing."""
    order_wire = {
        "a": coin_index,
        "b": is_buy,
        "p": float_to_wire(price),
        "s": float_to_wire(size),
        "r": False,  # not reduce only
        "t": order_type_to_wire(order_type),
    }

    return {
        "type": "order",
        "orders": [order_wire],
        "grouping": "na",
    }


def get_eip712_data(hash_hex: str, is_mainnet: bool):
    """Get the EIP-712 typed data structure for signing."""
    phantom_agent = construct_phantom_agent(hash_hex, is_mainnet)
    data = {
        "domain": {
            "chainId": 1337,
            "name": "Exchange",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "version": "1",
        },
        "types": {
            "Agent": [
                {"name": "source", "type": "string"},
                {"name": "connectionId", "type": "bytes32"},
            ],
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
        },
        "primaryType": "Agent",
        "message": phantom_agent,
    }
    return data


def get_multi_sig_action(multisig_address, outer_signer_address, action, signatures):
    multisig_address = multisig_address.lower()
    multi_sig_action = {
        "type": "multiSig",
        "signatureChainId": "0x66eee",
        "signatures": signatures,
        "payload": {"multiSigUser": multisig_address, "outerSigner": outer_signer_address.lower(), "action": action},
    }
    return multi_sig_action


def get_multi_sig_submission_data(multi_sig_action, nonce, is_mainnet):
    multi_sig_action_without_tag = multi_sig_action.copy()
    del multi_sig_action_without_tag["type"]
    multi_sig_action_hash = action_hash(multi_sig_action_without_tag, None, nonce)
    multi_sig_action_hash_hex = to_hex(multi_sig_action_hash)
    envelope = {
        "multiSigActionHash": multi_sig_action_hash_hex,
        "nonce": nonce,
    }

    return get_user_signed_action_data(envelope, MULTI_SIG_ENVELOPE_SIGN_TYPES, "HyperliquidTransaction:SendMultiSig", is_mainnet)


def get_user_signed_action_data(action, payload_types, primary_type, is_mainnet):
    action["signatureChainId"] = "0x66eee"
    action["hyperliquidChain"] = "Mainnet" if is_mainnet else "Testnet"
    data = {
        "domain": {
            "name": "HyperliquidSignTransaction",
            "version": "1",
            "chainId": 421614,
            "verifyingContract": "0x0000000000000000000000000000000000000000",
        },
        "types": {
            primary_type: payload_types,
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
        },
        "primaryType": primary_type,
        "message": action,
    }
    return data


def load_config():
    """Load configuration from config.json file."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path) as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading config.json: {e}")
        return None


def setup(skip_ws=False):
    """Set up connection to Hyperliquid API."""
    config = load_config()
    if not config:
        raise Exception("Failed to load configuration")

    multisig_address = config.get("multi_sig_user")
    if not multisig_address:
        raise Exception("Missing 'multi_sig_user' in config.json")

    is_mainnet = config.get("network") == "mainnet"
    if is_mainnet:
        base_url = constants.MAINNET_API_URL
    else:
        base_url = constants.TESTNET_API_URL

    multisig_config = config.get("multi_sig_signers", {})
    threshold = multisig_config.get("threshold", 0)
    outer_signer_address = multisig_config.get("outer_signer")
    signer_addresses = multisig_config.get("addresses", [])

    if not signer_addresses:
        raise Exception("No multisig signer addresses found in config")

    if not outer_signer_address:
        raise Exception("No outer signer address found in config")

    if outer_signer_address not in signer_addresses:
        raise ValueError("Outer signer address must be one of the signer addresses.")

    info = Info(base_url, skip_ws)
    exchange = Exchange(None, base_url, account_address=multisig_address)  # type: ignore

    # Check if account has equity
    try:
        user_state = info.user_state(multisig_address)
        margin_summary = user_state.get("marginSummary", {"accountValue": "0"})
        account_value = float(margin_summary.get("accountValue", "0"))
        print(f"Account value: {account_value}")
    except Exception as e:
        print(f"Warning: Could not fetch account state: {e}")

    return multisig_address, threshold, outer_signer_address, signer_addresses, info, exchange, is_mainnet


def get_coin_index(info, coin_name):
    """Get the coin index from the coin name."""
    try:
        meta = info.meta()
        for i, asset in enumerate(meta["universe"]):
            if asset["name"] == coin_name:
                return i
        raise ValueError(f"Coin {coin_name} not found in universe")
    except Exception as e:
        print(f"Error fetching coin index: {e}")
        return None


def main():
    # Check if config exists
    if not os.path.exists(os.path.join(os.path.dirname(__file__), "config.json")):
        print("Error: config.json file not found")
        return

    # Set up connection

    try:
        multisig_address, threshold, outer_signer_address, signer_addresses, info, exchange, is_mainnet = setup(skip_ws=True)

        print("\n=== multisig configuration ===")
        print(f"multisig address: {multisig_address}")
        print(f"threshold: {threshold} signatures required")
        print(f"signers: {', '.join(signer_addresses)}")
        print(f"outer signer: {outer_signer_address}")
        print(f"mainnet: {is_mainnet}")
        print("=============================")
    except Exception as e:
        print(f"Error setting up: {e}")
        return

    # Get order details
    print("\nAvailable coins:")
    meta = info.meta()
    for i, asset in enumerate(meta["universe"]):
        print(f"- {asset['name']}")

    coin_name = input("\nEnter the coin name (e.g., BTC): ").strip().upper()
    coin_index = get_coin_index(info, coin_name)
    if coin_index is None:
        return

    is_buy = input("Buy or Sell? (buy/sell): ").strip().lower() == "buy"

    size_input = input("Enter size: ").strip()
    try:
        size = float(size_input)
    except ValueError:
        print("Invalid size value")
        return

    order_type_input = input("Order type (limit/market): ").strip().lower()
    if order_type_input not in ["limit", "market"]:
        print("Invalid order type. Must be 'limit' or 'market'")
        return

    price = 0
    if order_type_input == "limit":
        price_input = input("Enter limit price: ").strip()
        try:
            price = float(price_input)
        except ValueError:
            print("Invalid price value")
            return
    else:
        # For market orders, fetch current price as reference
        try:
            price = exchange._slippage_price(
                name=coin_name,
                is_buy=is_buy,
                slippage=exchange.DEFAULT_SLIPPAGE,
            )
        except Exception as e:
            print(f"Error fetching price: {e}")
            price = 0  # Will use market price

    # Create order action
    order_action = create_order_action(coin_name, coin_index, is_buy, size, price, order_type_input)

    # Get timestamp for the order
    timestamp = get_timestamp_ms()

    # Generate typed data for each signer from config
    print("\n=== Typed Data for Signing ===")

    multi_sig_payload = [multisig_address.lower(), outer_signer_address.lower(), order_action]

    # Generate the hash
    action_hash_value = action_hash(multi_sig_payload, None, timestamp)
    hash_hex = to_hex(action_hash_value)

    # Get the EIP-712 typed data
    eip712_data = get_eip712_data(hash_hex, is_mainnet)

    print(f"Timestamp: {timestamp}")
    print("EIP-712 Typed Data Structure:")
    print(json.dumps(eip712_data))
    print("\nThis data needs to be signed with EIP-712 (eth_signTypedData_v4)")
    print("============================================================")

    # Collect signatures
    print(f"\n=== Collecting Signatures (minimum {threshold} required) ===")
    signatures = []

    for i, signer_address in enumerate(signer_addresses):
        print(f"Enter signature for signer #{i+1} ({signer_address}):")
        sig = input("Signature (hex string): ").strip()

        # Extract r, s, v from the hex signature if it's in that format
        if sig.startswith("0x"):
            sig = sig[2:]  # Remove 0x prefix

        try:
            r = "0x" + sig[:64]
            s = "0x" + sig[64:128]
            v = int(sig[128:130], 16)

            signatures.append({"r": r, "s": s, "v": v})
            print(f"Signature for signer #{i+1} processed successfully")
            print(f"Signature details: r={r}, s={s}, v={v}")
        except Exception as e:
            print(f"Error processing signature: {e}")
            return

    # Check if we have enough signatures
    if len(signatures) < threshold:
        print(f"Error: Not enough signatures. Required: {threshold}, Provided: {len(signatures)}")
        return

    # Generate multi-sig submission data
    print("\n=== Generating Multi-Sig Submission Data ===")
    try:
        multi_sig_action = get_multi_sig_action(multisig_address, outer_signer_address, order_action, signatures)

        multi_sig_data = get_multi_sig_submission_data(multi_sig_action, timestamp, is_mainnet)

        print("Multi-Sig Submission Data:")
        print(json.dumps(multi_sig_data))

        print(
            f"\n=== IMPORTANT ===\nThe Outer Signer ({outer_signer_address}) needs to sign the above data (using eth_signTypedData_v4).\n"
            "Please paste the signature below after the outer signer has signed it.\n"
            "===================\n"
        )
        outer_signer_signature = input("Outer Signer Signature: ").strip()
        # Extract r, s, v from the hex signature if it's in that format
        if outer_signer_signature.startswith("0x"):
            outer_signer_signature = outer_signer_signature[2:]  # Remove 0x prefix

        try:
            r = "0x" + outer_signer_signature[:64]
            s = "0x" + outer_signer_signature[64:128]
            v = int(outer_signer_signature[128:130], 16)

            multi_sig_action_signature = {"r": r, "s": s, "v": v}
            print(f"Signature details: r={r}, s={s}, v={v}")
        except Exception as e:
            print(f"Error processing signature: {e}")
            return

    except Exception as e:
        print(f"Error generating multi-sig submission data: {e}")
        return

    # Submit order with the complete multi-sig data
    print("\n=== Submitting Order with Multi-Sig Data ===")
    try:
        response = exchange._post_action(multi_sig_action, multi_sig_action_signature, timestamp)
        print("\nOrder submission result:")
        print(json.dumps(response))

        if response.get("status") == "ok":
            print("\nOrder successfully submitted!")
        else:
            print("\nOrder submission failed.")
    except Exception as e:
        print(f"Error submitting order: {e}")


if __name__ == "__main__":
    main()
