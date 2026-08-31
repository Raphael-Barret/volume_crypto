# voltcrypt, encryption for volumetric imaging files

**AES-256-GCM** encryption of imaging files (`.vtk`, `.nii`, `.nii.gz`,
`.nrrd`, `.mha`, `.dcm`, `.stl`, and so on), one file at a time or a whole
folder, with generation of the decryption key.

> **Step-by-step guide, use cases and troubleshooting:
> [GUIDE_UTILISATION.md](GUIDE_UTILISATION.md) (in French).**
> This README gives the overview and the format details.

Designed for volumes of several GB: reads in 4 MiB blocks, never loads a whole
file into RAM. Measured on this machine: **~320 MB/s encrypting, ~470 MB/s
decrypting**, for a size overhead of ~2.7 kB on 512 MB.

---

## Installation

The project uses [uv](https://docs.astral.sh/uv/). If you do not have it yet:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then, in this folder:

```bash
uv sync     # creates .venv and installs cryptography, that is all
```

## Three commands to use it

```bash
cd volume_crypto

uv run main.py gen-key      # 1. generates data/keys/master.key  (once)
uv run main.py encrypt      # 2. data/to_encrypt/  ->  data/encrypted/
uv run main.py decrypt      # 3. data/encrypted/   ->  data/decrypted/
```

`uv run` creates and updates the environment on its own, so `uv sync` is not
even required: the first command takes care of it.

Three commands to check the result:

```bash
uv run main.py list         # original name and size of each .enc
uv run main.py check        # "can I still read my files?"    (key + sha256)
uv run main.py audit        # "are they really unreadable?"   (7 controls)
```

`audit` checks the entropy of the container, the absence of any format
signature or of the original name in the clear, the sha256 round trip, and, if
the original is still present, that no fragment of it can be found inside the
`.enc`. See
[the dedicated section of the guide](GUIDE_UTILISATION.md#5-verifier-que-le-chiffrement-est-correct).

## Client and server pipeline

An end-to-end demonstration ships with the project: the volume is encrypted on
the workstation, sent over HTTP, and **the key is released to the server only
once it has proved which code it runs**.

```bash
uv run server.py                                          # terminal 1
uv run client.py data/to_encrypt/volume.nii.gz --trust-on-first-use   # terminal 2
```

Change a single line of `server.py` and the client refuses to hand over the
key. See [PIPELINE.md](PIPELINE.md) for the protocol, its guarantees and its
limits.

## Folder layout

```
volume_crypto/
├── pyproject.toml          # dependencies (managed by uv)
├── main.py                 # command line
├── server.py               # processing server (pipeline)
├── client.py               # clinical workstation (pipeline)
├── verify.py               # client-side verification of the announced code
├── parity_experiment.py    # clear-text against encrypted-chain comparison
├── evidence_report.py      # collects the measurements into JSON
├── voltcrypt/
│   ├── config.py           # <- paths, block size, extensions (edit here)
│   ├── keys.py             # key generation and storage
│   ├── crypto.py           # encryption of ONE file (the core)
│   ├── batch.py            # encryption of a FOLDER
│   ├── audit.py            # verification controls (audit command)
│   ├── timing.py           # timing and duration formatting
│   ├── attestation.py      # proof of the executed code (pipeline)
│   └── keyexchange.py      # encrypted key release (pipeline)
├── tests/
│   ├── test_keys.py        # unit tests
│   ├── test_crypto.py
│   ├── test_batch.py
│   ├── test_audit.py
│   ├── test_timing.py
│   ├── test_pipeline.py
│   ├── conformance/        # protocol properties and seeded-defect detection
│   └── integration/        # parity against a real tool
└── data/
    ├── to_encrypt/         # <- drop your volumes here
    ├── encrypted/          # -> .enc files
    ├── decrypted/          # -> restored files
    └── keys/               # <- THE KEYS. Never share, never commit.
```

The directory tree is preserved:
`to_encrypt/patient_01/T1/scan.nii` becomes
`encrypted/patient_01/T1/scan.nii.enc`.

## Useful options

```bash
# Folders other than the defaults
uv run main.py encrypt -i /media/disk/CBCT -o /media/nas/encrypted

# One key per study
uv run main.py gen-key --key data/keys/study_ALI.key --label "ALI study 2026"
uv run main.py encrypt --key data/keys/study_ALI.key

# Encrypt only volumetric extensions (skip README, .csv, and so on)
uv run main.py encrypt --only-volumes

# Reprocess files that were already produced
uv run main.py encrypt --overwrite
```

By default an output file that already exists is **skipped**, so running the
command again only does the remaining work. That helps on a large batch that
was interrupted.

## Use from Python

```python
from voltcrypt import crypto, keys, batch

key = keys.get_or_create_key("data/keys/master.key")

# One file: the return value carries the path AND the duration
result = crypto.encrypt_file("scan.nii.gz", "scan.nii.gz.enc", key)
print(result.seconds)           # 0.4702
print(result)                   # scan.nii.gz.enc : 132.5 Mo en 470.2 ms (282 Mo/s)

crypto.decrypt_file("scan.nii.gz.enc", "scan_restored.nii.gz", key)

# One folder
batch_result = batch.encrypt_directory("my_volumes/", "encrypted/", key)
print(batch_result.wall_seconds, batch_result.timing_summary())

# With a progress bar
crypto.encrypt_file(src, dst, key,
                    progress=lambda done, total: print(f"\r{100*done//total} %", end=""))
```

## Tests

```bash
cd volume_crypto
uv run python -m unittest discover -s tests -t . -v     # 158 tests, 3 skipped
# or
uv run pytest tests -v                                  # pytest comes from the dev group
```

The unit tests cover the bit-for-bit round trip (VTK ASCII, binary, empty file,
file larger than the block size), refusal of a wrong key, detection of a flipped
bit or of a truncation, and the behaviour of a batch when one file is corrupt.
The `conformance/` tests check protocol properties and that the verifier catches
deliberately seeded defects; `integration/` compares a real tool run against its
clear-text control. The three skipped tests need a GPU and a served tool.

---

## What the `.enc` format does

```
HEADER (21 bytes, in the clear)
    magic "VOLCRYPT" | version | block size | nonce_base (8 random bytes)

then a sequence of BLOCKS:  [length 4 bytes][ciphertext || GCM tag 16 bytes]

    block 0        encrypted metadata: original name, size
    block 1..n     file data
    final block    sha256 of the plaintext content
```

- **Nonce** = `nonce_base || block index`. Since `nonce_base` is drawn at random
  for every file, no nonce is ever reused with the same key, which is the
  critical point of GCM.
- **AAD** of each block = header + index + "last block" flag. A block therefore
  cannot be reordered, removed, duplicated, or copied over from another file,
  and truncation of the file is detected.
- **The original name is encrypted**: `DUPONT_Jean_CBCT.vtk` appears nowhere in
  the clear inside the container. You can rename the `.enc` files freely, to
  pseudonyms for instance, and `decrypt` recovers the original name from the
  metadata.
- **Atomic writes**: every output is written as `.part` then renamed. An
  interruption never leaves a half-written file that would look valid.

## What this project does not do

- **It does not protect the key.** `data/keys/master.key` sits in the clear on
  disk, mode 0600. Whoever reads that file reads your volumes. For real patient
  data: back the key up offline, and look at a KMS or an HSM, or at key release
  conditioned on an attestation (see `../conf_computing.md`).
- **It only protects data at rest.** During computation the data is in the clear
  in memory.
- **It does not anonymise.** Encryption is reversible by design: encrypted data
  whose key you hold remains personal data under the GDPR. Strip identifying
  DICOM metadata *before* encrypting, because everything you encrypt comes back
  unchanged on decryption. Details in
  [section 6 of the guide](GUIDE_UTILISATION.md#6-chiffrement-pseudonymisation-anonymisation).
- **Losing the key means losing the data.** There is no recovery. That is the
  intended behaviour, but do back up `data/keys/`.
- **No compression.** An uncompressed `.nii` stays just as large once
  encrypted. Compress first (`.nii.gz`) if you need to, because after encryption
  nothing compresses any more.

## Adapting it

Almost everything is set in [`voltcrypt/config.py`](voltcrypt/config.py):
folder paths, `CHUNK_SIZE`, recognised extensions. The rest of the code only
reaches them through those constants.
