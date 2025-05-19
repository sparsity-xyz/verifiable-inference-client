# Verifiable Inference Client Tutorial

This short guide walks you through running the sample client that interacts with the Sparsity platform and verifies responses from a Trusted Execution Environment (TEE).

For more background on Sparsity and how verification works, see the [official documentation](https://sparsity.gitbook.io/sparsity-platform).

## 1. Install prerequisites

Ensure you have **Python 3.8+** available. Then install the Python packages required by the client:

```bash
pip install -r requirements.txt
```

## 2. Configure environment variables

The client expects several variables to be set so it knows which AI provider to contact and where the TEE is hosted.

```bash
export PYTHONPATH="$PYTHONPATH:$PWD"          # so Python can find the local modules
export PLATFORM_API_KEY=<YOUR_OPENAI_KEY>      # API key for the model provider
export PLATFORM=openai                         # name of the provider
export MODEL=gpt-4                             # model to query
export TEE_TLS_URL=http://127.0.0.1:8000/      # URL of the Sparsity TEE service
```

Replace `<YOUR_OPENAI_KEY>` with a valid key from your account. You can adjust `PLATFORM`, `MODEL`, and `TEE_TLS_URL` to use a different provider or endpoint.

## 3. Run the client

With the variables in place, execute:

```bash
python3 main.py
```

The program requests an attestation from the TEE, encrypts your prompt, and prints the response along with a signature verification result. A successful run looks like:

```
Verifying TEE Enclave Identity: True
prompt: Bitcoin Price today right now
raw response: {...}
verify signature: True
```

If `verify signature` is `True`, the response was produced by the TEE and signed correctly.

## 4. Next steps

You can modify `main.py` or `client.py` to send your own prompts or integrate this verification logic into a larger application. The [Sparsity Platform documentation](https://sparsity.gitbook.io/sparsity-platform) explains the attestation process and available APIs in more detail.

