# Hyperliquid Multi-Sig Order Submission Tool

This tool facilitates submitting orders on the Hyperliquid DEX using a multi-signature (multi-sig) wallet. It handles the creation of the order action, generation of the necessary EIP-712 typed data for signing, collection of signatures from multiple signers, and submission of the signed transaction to Hyperliquid.

## Features

*   **Multi-Sig Support:** Enables secure order placement through multi-signature authorization.
*   **EIP-712 Compliance:** Uses EIP-712 for structured and secure message signing.
*   **Flexible Order Creation:** Supports different order types (limit and market).
*   **Configuration Driven:** Uses a `config.json` file for configuring multi-sig parameters and network settings.
*   **User-Friendly Interface:** Provides a command-line interface for easy interaction.
*   **`uv` Package Management:** Uses the lightning-fast `uv` package manager for dependency resolution and installation.

## Prerequisites

*   **Python 3.13+**:  This project is designed for Python 3.13 according to the `pyproject.toml` file.
*   **`uv` Package Manager**: A fast and modern Python package installer and resolver. Install `uv` following the instructions on its repository.
    *   **Installation Link:**  [https://github.com/astral-sh/uv](https://github.com/astral-sh/uv) Follow the installation instructions specific to your operating system on the linked `uv` GitHub repository.
*   **Hyperliquid Account:** You need to have a Hyperliquid account.
*   **Multi-Sig Wallet:**  You need to have a deployed multi-sig wallet contract.
*   **Signers:**  You need to have access to the private keys or signing capabilities of the signers configured in your `config.json` file.
*   **Funding:** The multi-sig account needs to have sufficient funds for trading.

## Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/tholos-inc/hyperliquid-multisig-cli.git
    cd hyperliquid-multisig-cli
    ```

2.  **Create a `config.json` file:** Copy the `config.example.json` file in the repository to `config.json` and modify it with your specific multi-sig setup:  (refer to sample `config.example.json` in repository)

    ```json
    {
      "multi_sig_user": "YOUR_MULTI_SIG_USER_ADDRESS",
      "network": "testnet",
      "multi_sig_signers": {
        "threshold": 1,
        "outer_signer": "YOUR_OUTER_SIGNER_ADDRESS",
        "addresses": [
          "YOUR_SIGNER_ADDRESS_1",
          "YOUR_SIGNER_ADDRESS_2",
          "YOUR_SIGNER_ADDRESS_3"
        ]
      }
    }
    ```

    *   **`multi_sig_user`**:  The Ethereum address of your multi-sig contract.
    *   **`network`**:  `"mainnet"` for the main network, `"testnet"` or other custom value for appropriate test.
    *   **`multi_sig_signers`**:
        *   **`threshold`**:  The minimum number of signatures required to execute the transaction (quorum).
        *   **`outer_signer`**: The Ethereum address of intended outer signer to sign the final hash of the submitted multi-sig action.
        *   **`addresses`**:  A list of Ethereum addresses that are authorized signers for the multi-sig.
            * **Note**: The `outer_signer` must exist in this list.

    **Important:** NEVER commit your `config.json` with to a public repository. Ensure it is in your `.gitignore` file.


## Usage

1.  **Run the script:**

    ```bash
    uv run main.py
    ```

2.  **Follow the prompts:** The script will guide you through the process of creating an order, generating the EIP-712 typed data, collecting signatures, and submitting the transaction.

    1.  It will first ask you for order details: coin name, order type (limit/market), size, and price (if limit order).
    2.  It will then display the EIP-712 typed data that each signer needs to sign using `eth_signTypedData_v4`.
    3.  You'll need to collect signatures from the signers specified in `config.json`.  You will be prompted to enter the signatures, one by one.
    4.  After collecting enough valid signatures, it will proceed with submitting the order to Hyperliquid via the appropriate API endpoint.

## Workflow

1.  **Configuration:** Load the `config.json` file to retrieve multi-sig and network settings.
2.  **Order Creation:**  The script prompts for details about the order: coin, buy/sell, size, and price.  It creates an order 'action'.
3.  **Action Hashing:** The script constructs payload and generate the typed hash of the data for signers to sign.
4.  **EIP-712 Data Generation:** It then constructs the EIP-712 typed data structure for signing, incorporating the required domain and message parameters. Then outer signer needs to sign the multi-sig action.
5.  **Signature Collection:** Collect the necessary number of signatures from the configured signers by providing the EIP-712 data to them (e.g., using a wallet like MetaMask or hardware wallet.)
6.  **Transaction Submission:** Finally, the script posts the multi-sig action, constructed with collected signatures to Outer Signer for Signature, and then complete data to Hyperliquid Exchange API to submit the order.

## Security Considerations

*   **Protect `config.json`:**  Never commit this file with actual keys to a public repository.  Use `.gitignore`.
*   **Use Testnet:**  Always test the script and your multi-sig setup on a testnet before using it on mainnet.
*   **Verify Addresses:**  Double-check all addresses in `config.json` to ensure they are correct.

## Disclaimer

Use this tool at your own risk. The developers are not responsible for any financial losses incurred while using this script. Always exercise caution and thoroughly test your multi-sig setup before trading with real funds.
