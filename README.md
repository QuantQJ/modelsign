# modelsign

Sign AI models with identity. Verify anywhere.

`modelsign` cryptographically binds model files to a signed identity card — who made this model, what it's based on, what it claims to be. Ed25519 signatures, zero ML dependencies, works with any model format.

## Install

```bash
pip install modelsign
```

## Quick Start

```bash
# Generate your signing key
modelsign keygen

# Sign a model with a name
modelsign sign model.safetensors --name "My-Llama-8B-v1"

# Verify it
modelsign verify model.safetensors

# Inspect the identity card
modelsign inspect model.safetensors.sig
```

## Rich Identity Cards

Sign with full provenance:

```bash
# Create an identity card
cat > card.json << 'EOF'
{
  "name": "Llama-3.1-8B-Chat-QJ",
  "architecture": "LlamaForCausalLM",
  "base_model": "meta-llama/Llama-3.1-8B-Instruct",
  "version": "1.0.0",
  "creator": "ConstantQJ",
  "license": "Llama 3.1 Community",
  "intended_use": "Chat assistant",
  "training": {
    "dataset": "custom-chat-v2",
    "epochs": 3,
    "hardware": "DGX Spark GB10"
  },
  "eval_metrics": {
    "mmlu": 0.68,
    "humaneval": 0.53
  }
}
EOF

modelsign sign model.safetensors --identity card.json
```

## Python SDK

```python
from modelsign import (
    ModelCard, validate_card, canonical_json,
    generate_keypair, load_private_key, load_public_key,
    sign_bytes, build_file_message, verify_bytes,
    hash_file, SigFile, write_sig, read_sig,
)
```

## What It Protects Against

- Post-signing **tampering** of model weights
- **Substitution** of one model for another
- **Metadata swap** (changing identity claims invalidates signature)

## What It Does NOT Cover

- Key compromise (your key, your responsibility)
- Model safety, fairness, or legal compliance
- Cryptographic timestamping (timestamps are metadata, not proofs)

## License

MIT — QJ / ConstantOne (CIP1 LLC)
