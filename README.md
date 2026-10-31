# modelsign

[![CI](https://github.com/QuantQJ/modelsign/actions/workflows/ci.yml/badge.svg)](https://github.com/QuantQJ/modelsign/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-%E2%98%95-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/qjkerr1)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github)](https://github.com/sponsors/QuantQJ)

**Unsigned model weights fail to load.**

A signature nothing checks protects nothing. `modelsign` puts the check in the place every Python ML stack passes through — the Hugging Face Hub download path — so weights that are unsigned, modified, or signed by a key you don't trust raise an exception instead of loading.

It reads and writes [OpenSSF Model Signing](https://github.com/google/model-transparency) bundles, so it works in projects that have already standardized on OMS.

```bash
pip install modelsign
```

## Fail closed at load time

```python
import modelsign.guard as guard

guard.install(pubkey="~/keys/vendor.pem")          # or set MODELSIGN_PUBKEY

from transformers import AutoModel
AutoModel.from_pretrained("acme/llama-8b")         # LoadBlocked unless it verifies
```

One hook covers `transformers`, `sentence-transformers`, `diffusers` and vLLM, because they all download through `huggingface_hub`. The guard:

- fetches `MODEL.sig` from the same repo as the weights rather than hoping it is already on disk;
- refuses a download with **no** signature (`allow_unsigned=True` if you must);
- requires a signature for **every** file in a snapshot, so an unsigned `pytorch_model.bin` cannot ride along beside a signed `model.safetensors`;
- accepts an OMS bundle on equal footing when you pass `oms_pubkey=` (or `MODELSIGN_OMS_PUBKEY`).

To check a path yourself:

```python
from modelsign.guard import require_verified, LoadBlocked

try:
    result = require_verified("./model.safetensors", pubkey="vendor.pem")
except LoadBlocked as e:
    ...
```

## Sign and verify

```bash
modelsign keygen                                   # Ed25519 keypair
modelsign sign model.safetensors --name "My-Llama-8B-v1"
modelsign verify model.safetensors --pubkey public.pem
modelsign inspect model.safetensors.sig
```

Signing a directory produces one signature over a manifest of every file, so an added or swapped file breaks verification. That is the form to prefer for a multi-file model.

In CI, demand a known signer — an embedded key proves the bytes are unchanged and nothing about who signed them:

```bash
modelsign verify ./model --require-trusted --pubkey vendor.pem
```

## Python API

```python
from modelsign import sign_model, verify_model

sign_model("model.safetensors", name="My-Llama-8B-v1", key="private.pem")

result = verify_model("model.safetensors", pubkey="public.pem")
result.verified      # the signature is valid and the bytes are unchanged
result.trusted       # ...and the signer was checked against a key you already had
result.identity      # the signed identity card
```

`verify_model` returns a falsy `VerifyResult` for a failed check and raises `VerifyError` only when the check cannot be attempted. Nothing prints; nothing calls `sys.exit`.

## OpenSSF Model Signing interoperability

```bash
modelsign oms keygen                               # ECDSA P-256 (OMS rejects Ed25519)
modelsign oms export ./model --key oms_private.pem --out ./model/model.sig
modelsign oms verify ./model --pubkey oms_public.pem
```

Bundles written by `modelsign oms export` verify with the `model-signing` CLI, and bundles written by `model-signing sign key` verify here. Both directions are covered by tests, including golden digests captured from `model-signing`'s own output.

`modelsign`'s OMS verification is stricter in one respect: a file on disk that is **not** in the signed manifest fails the check, rather than being ignored.

A directory signature covers every file in the directory, so writing an OMS
bundle into a directory you have already signed with `modelsign sign` will
invalidate that signature. Either keep the bundle outside the directory, or
sign the directory after writing it.

## Identity cards

A signature covers an identity card as well as the bytes, so changing a claim invalidates the signature:

```json
{
  "name": "Llama-3.1-8B-Chat-QJ",
  "base_model": "meta-llama/Llama-3.1-8B-Instruct",
  "architecture": "LlamaForCausalLM",
  "creator": "ConstantQJ",
  "license": "Llama 3.1 Community",
  "intended_use": "Chat assistant",
  "training": {"dataset": "custom-chat-v2", "epochs": 3, "hardware": "DGX Spark GB10"},
  "eval_metrics": {"mmlu": 0.68, "humaneval": 0.53}
}
```

```bash
modelsign sign model.safetensors --identity card.json
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Model name |
| `architecture` | No | Model class (e.g. `LlamaForCausalLM`) |
| `base_model` | No | Parent model name or path |
| `parent_signature` | No | Hash of the parent's `.sig` (provenance chain) |
| `version` | No | Semantic version |
| `creator` | No | Person or organization |
| `license` | No | SPDX identifier or name |
| `intended_use` | No | What the model is for |
| `restrictions` | No | What it should not be used for |
| `training` | No | `{dataset, dataset_hash, epochs, hardware}` |
| `quantization` | No | Method (e.g. `GPTQ-4bit`) |
| `eval_metrics` | No | Benchmark results (`{mmlu: 0.68}`) |
| `extra` | No | Any additional metadata |

## Use it in CI

Signing earns its keep where a build refuses to proceed. The bundled action
installs `modelsign` and fails the job on an unverified model:

```yaml
- uses: QuantQJ/modelsign@v1
  with:
    model: ./model
    pubkey: ./keys/vendor.pem        # require-trusted is on by default
```

For a repository signed with OpenSSF Model Signing:

```yaml
- uses: QuantQJ/modelsign@v1
  with:
    model: ./model
    oms-pubkey: ./keys/oms_public.pem
```

If `modelsign` is already on `PATH` and no `version` is pinned, the action uses
it rather than installing another copy.

## How it compares

OMS is the OpenSSF specification and the thing to standardize on. `modelsign` reads and writes it; the differences are in what else each one does.

| | modelsign | OpenSSF Model Signing |
|---|---|---|
| Format | own `.sig`, plus OMS bundles both ways | OMS sigstore bundle |
| Signing methods | Ed25519 key; ECDSA P-256 for OMS output | Sigstore (default), private key, certificate, PKCS #11 |
| Transparency log | no | optional — used by Sigstore signing, not by key signing |
| Works offline | yes | yes, with `sign key` |
| Signed payload | file manifest **and** an identity card (base model, license, eval metrics) | file manifest; model-card fields are listed as future work |
| Verification at model load | yes, via `guard.install()` | not provided |
| Kubernetes admission | no | yes, via the sigstore Model Validation Operator |
| CI identity | no | yes — GitHub Actions, GitLab CI, GCP, Buildkite workload identity |

Use OMS when you need keyless signing tied to a CI identity, a transparency log, or cluster admission control. Use `modelsign` when you need load-time enforcement, a signed identity card, or signing in a place that cannot reach Sigstore.

## What it protects against

- Post-signing **tampering** with model weights
- **Substitution** of one model for another
- **Metadata swap** — changing an identity claim invalidates the signature
- **Smuggling** — an unsigned file added beside signed ones

## What it does not cover

- Key compromise — your key, your responsibility
- Model safety, fairness, or legal compliance
- Cryptographic timestamping; `signed_at` is metadata, not proof (no RFC 3161 timestamp)
- Pickle and deserialization attacks inside a correctly signed file

## License

Apache 2.0
