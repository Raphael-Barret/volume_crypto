# Imaging Data Protection — Architecture and Guarantees

**Reference document.** Describes how 3D medical imaging volumes are protected,
what that protection guarantees, what it does not, and how to verify it
independently.

Written for three different readings:

| You are | Read |
|---|---|
| decision maker, privacy officer, IRB member | sections 1, 2 and 7 |
| clinician or system user | sections 1 through 4 |
| technical auditor, engineer | everything, particularly sections 5, 6 and 8 |

---

## 1. One page summary

**The problem.** Analyzing a 3D scan (CBCT, MRI) with AI tools requires
computing power a clinical workstation does not have, so the study must be sent
to a remote server. But a cranial imaging study is identifiable health
information: the volume contains the patient's face, and the files usually carry
their name.

**The conventional answer, and its limits.** Standard practice is *defacing* —
digitally erasing the face before transfer. This irreversibly degrades the
study, removes soft tissue that may be diagnostically relevant, and introduces
artifacts near the sinuses and nasal bone. It is also not anonymization in the
strict sense: re-identification from bone geometry remains debated in the
literature.

**Our approach.** Do not degrade the data. Instead, make it unusable to anyone
not explicitly authorized, at every stage:

1. **On the clinical workstation** — the study is encrypted before it leaves the
   machine. What travels over the network is a byte stream with no readable
   structure.
2. **In transit and at rest** — without the key, the file carries no usable
   information, including the patient's name.
3. **During computation** — processing runs inside a hardware enclave whose
   memory is encrypted by the processor itself. Neither the server
   administrator, nor the hosting provider, nor the cloud vendor can read the
   data while it is being analyzed.
4. **The key is released only to proven code** — the workstation transmits the
   decryption key only after receiving cryptographic proof, signed by the
   processor manufacturer, that the server is running exactly the intended
   program in an isolated environment.

**What this changes.** The argument shifts from degradation ("we damaged the
data so it is no longer identifiable") to **verifiable confidentiality** ("the
data is intact, and here is a manufacturer-signed proof that only the audited
code can access it").

**Deployment status.** Points 1 and 2 are **implemented, tested and measurable
today** (section 5). Points 3 and 4 describe a server architecture **currently
in design** (section 6). This document distinguishes the two throughout.

---

## 2. Questions we are asked

### "Is encryption the same as putting a password on a file?"

No, and the difference matters. A password protects *access*: the file stays
intact and a program checks whether you are allowed to open it. Bypass the
program and the file is still there.

Encryption transforms the *content*. An encrypted file no longer contains the
study in readable form — it contains a byte stream whose structure is gone.
There is nothing to bypass: without the key, there is no known way to recover
the image, regardless of the software used.

For scale: the key is 256 bits, a number with 78 digits. Trying every
combination is beyond what is physically achievable, and that claim does not
rest on our judgment — AES-256 is the standard selected by NIST and used to
protect classified information.

### "If a file is encrypted, does that mean the patient can no longer be identified?"

**No**, and this is the most important point in this document.

Encryption is *reversible by design* — that is the entire point, since the
clinician must be able to read the study back. As long as a key exists
somewhere, the data remains linkable to a person.

Under HIPAA, encrypted imaging remains **protected health information**.
Encryption is a security safeguard, not a de-identification method: the Privacy
Rule recognizes only Safe Harbor (§164.514(b)(2)) and Expert Determination
(§164.514(b)(1)). Under GDPR, encrypted data whose key you hold is **pseudonymized
personal data** (Art. 4(5)), not anonymous data (Recital 26). Every obligation
continues to apply.

| | Reversible? | Regulatory status | What it protects against |
|---|---|---|---|
| **Encryption** | yes, with the key | PHI / personal data | access by a third party without the key |
| **Pseudonymization** | yes, with the mapping | PHI / personal data | direct identification |
| **De-identification** (Safe Harbor / Expert Determination) | no | outside PHI scope | identification, permanently |
| **Defacing** | no, but partial | debated | facial recognition from the volume |

Worth noting for cranial imaging specifically: Safe Harbor lists "full face
photographic images and any comparable images" among the 18 identifiers that
must be removed. A CBCT volume containing the face falls squarely in that
category — which is precisely why defacing became common practice, and why
replacing it requires a defensible alternative safeguard.

What encryption genuinely provides: it sharply reduces risk in the event of a
breach, it satisfies the addressable encryption specification of the HIPAA
Security Rule (§164.312(a)(2)(iv) and §164.312(e)(2)(ii)), and it can remove the
obligation to notify — see section 8.

### "Who can read my studies?"

Today, with encryption in place: **anyone holding the key file**, and no one
else. The key does not leave the clinical workstation until the server
architecture (section 6) is deployed.

This answer is deliberately narrow. It also means that protecting that key file
is the critical point of the entire design — see section 7.

---

## 3. The end-to-end chain

```
   CLINICAL WORKSTATION                              COMPUTE SERVER
   ────────────────────                              ──────────────

   original study
   (intact, not degraded)
        │
        │ strip identifying metadata
        │ (name, date of birth, accession number)
        ▼
   AES-256-GCM encryption ─────── key K ──────┐
        │                     (stays local)   │
        ▼                                     │
   .enc file                                  │  ┌─────────────────────────┐
        │                                     │  │  hardware enclave       │
        │────────── network transfer ─────────┼─▶│  memory encrypted by    │
        │        (content unreadable)         │  │  the processor          │
        │                                     │  │                         │
        │◀───── attestation evidence ─────────┼──┤  proves which code      │
        │       signed by the manufacturer    │  │  it is running          │
        │                                     │  │                         │
        │  verify the evidence                │  │                         │
        │  (code measurement, isolation,      │  │                         │
        │   firmware versions, policy)        │  │                         │
        │                                     │  │                         │
        └────── K, encrypted for the enclave ─┼─▶│  decrypt in memory      │
                                              │  │  AI inference           │
                                              │  │  re-encrypt the result  │
   result decrypted locally ◀─────────────────┼──┤  wipe, destroy VM       │
                                              │  └─────────────────────────┘
```

The key point: **the key is sent only after verification**, and it is encrypted
specifically for the enclave that produced the evidence. An intercepted copy is
unusable.

---

## 4. What is protected, and against whom

A security system cannot be described in the abstract — only against a stated
adversary. Here is the explicit list.

| Scenario | Protected? | Why |
|---|---|---|
| Stolen or lost drive holding encrypted files | **yes** | without the key, no usable information |
| Network transfer intercepted | **yes** | the payload is already encrypted |
| Storage server compromised | **yes** | files are stored encrypted |
| Backups accidentally exposed | **yes** | same reason |
| System administrator of the compute server | **yes, with the TEE** (section 6) | memory is encrypted by the processor |
| Hosting or cloud provider | **yes, with the TEE** | the hypervisor is outside the trust boundary |
| Key file stolen from the workstation | **no** | whoever holds the key reads the data |
| Workstation compromised before encryption | **no** | the data is in the clear there by nature |
| Authorized person who deliberately exfiltrates | **no** | a matter of access control and audit logging, not encryption |

That last column is what a serious audit examines first. A system claiming to
protect against everything has not been analyzed.

---

## 5. Layer 1 — file encryption (in place)

### What is used

**AES-256 in GCM mode.** AES is standardized by NIST (FIPS 197); GCM likewise
(SP 800-38D). These are not in-house choices — they are what TLS, disk
encryption and major cloud providers use.

GCM adds a property beyond confidentiality: **authentication**. A single flipped
bit in an encrypted file is detected at decryption, which fails rather than
silently producing a corrupted image. For diagnostic imaging, that integrity
guarantee matters as much as confidentiality.

**No cryptography was written for this project.** All cryptographic operations
are delegated to the `cryptography` library from the Python Cryptographic
Authority, backed by OpenSSL. The project code arranges the calls; it implements
no algorithm. This is a baseline requirement: home-grown cryptography is the
leading cause of failure in systems of this kind.

### Properties obtained

- **The patient name does not leak through the filename.** The original name is
  stored *inside* the encrypted region. A file named `DOE_John_CBCT.vtk` becomes
  a container in which the string "DOE" appears nowhere. Files can be renamed to
  pseudonyms with no loss — the real name is restored at decryption.
- **Encrypting the same study twice produces two different files.** Comparing
  two encrypted files reveals nothing about whether they hold the same study.
- **Block reordering, truncation and substitution are detected.** Each block is
  authenticated together with its position and an end-of-file marker; a block
  cannot be moved, duplicated, removed, or copied in from another file.
- **No partial files are ever produced.** Output is written to a temporary file
  and renamed on completion. A power loss never leaves an incomplete file that
  could pass for valid.
- **Size does not grow.** Roughly 2.7 KB of overhead on 512 MB.

### Measured performance

Measured on a Linux workstation, on a real 132.5 MB CBCT:

| Operation | Throughput | Time on this CBCT |
|---|---|---|
| Encryption | ~390 MB/s | 0.34 s |
| Decryption | ~430 MB/s | 0.31 s |

Encryption is therefore not a bottleneck in clinical workflow: it costs under a
second per study, and the limiting factor is disk I/O, not cryptography.

### How to verify it independently

These checks are reproducible by a third party, without trusting us.

**1. The automated test suite.** 80 tests, run with a single command
(`uv run python -m unittest discover -s tests -t .`). They cover byte-exact round
trips on real data, rejection of a wrong key, detection of a single modified
bit, detection of truncation, and behavior when one file in a batch is corrupt.

**2. The built-in audit command** (`audit`). It applies seven checks to each
encrypted file:

| Check | Question it answers |
|---|---|
| structure | is the container well formed? |
| entropy | is the content statistically indistinguishable from random data? |
| format signatures | does any known file signature (VTK, NIfTI, DICOM, gzip…) appear in the clear? |
| original name | is the filename readable inside the container? |
| round trip | does decryption reproduce the original exactly (SHA-256 digest)? |
| identical to original | does the restored file's digest match the original's? |
| fragment leakage | does any fragment of the original appear verbatim in the container? |

Actual output on a real CBCT (the tool's messages are in French; glosses added):

```
  PASS  C_0001_T1.nii.gz.enc
    [ok  ] structure              header VOLCRYPT valide          → well-formed container
    [ok  ] entropie               8.000 bits/octet (seuil 7.800)  → 8.000 bits/byte (threshold 7.800)
    [ok  ] signatures format      aucune trouvee                  → none found
    [ok  ] nom d'origine          'C_0001_T1.nii.gz' absent       → filename absent from container
    [ok  ] round-trip             dechiffre, sha256 verifie       → decrypted, SHA-256 verified
    [ok  ] identique a l'original sha256 restitue == sha256 origine
    [ok  ] fuite de fragments     0 fragment de l'original        → 0 fragments of the original
```

An entropy of 8.000 bits per byte is the maximum possible value: it means no
statistical structure is detectable in the file.

**3. An important methodological point.** These are *positive* checks — they
verify an expected property. Observing that a viewer refuses to open the
encrypted file proves nothing: a corrupted file fails the same way. The test
suite deliberately includes *fake* encryption cases (a plaintext file simply
renamed, a trivial byte inversion) and verifies that the audit rejects them.

**4. Code review.** The encryption module is 268 commented lines; the whole
library is under 1,000. That is an hour of reading for an engineer, and it is
deliberate: a security component that cannot be read cannot be audited.

---

## 6. Layer 2 — confidential computing (to be deployed)

This section describes the target architecture. **It is not deployed today.** It
is documented here because it determines the scope of the guarantees claimed
above.

### The problem it solves

Layer 1 protects data *at rest* and *in transit*. But analyzing a study requires
decrypting it somewhere. At that moment, on an ordinary server, the image sits
in the clear in memory, and several parties can read it: the machine
administrator, the hypervisor managing virtualization, the hosting provider.
This is a structural property of conventional virtualization, not a
misconfiguration.

### The principle

Recent processors (AMD SEV-SNP, Intel TDX) include an encryption engine between
the processor and the memory modules. Data belonging to a protected virtual
machine is encrypted in memory with a key **generated inside the processor and
not extractable** — no instruction exists to read it, not even for the host
operating system. The performance cost is a few percent.

Recent NVIDIA GPUs (H100 and later) offer an equivalent mode, required here
since AI inference runs on GPU.

### Attestation: what turns trust into proof

This is the central mechanism, and the one with the most value for a regulatory
submission.

At startup, the enclave produces a **processor-signed report** containing, among
other things, a measurement of everything loaded into memory (firmware, kernel,
program), firmware versions, and the active security policy. The signature
chains back to a key fused into the chip at manufacture and certified by the
vendor.

Concretely, the clinical workstation can verify, **before** transmitting
anything:

- that the server runs exactly the published, audited program, byte for byte —
  any modification changes the measurement;
- that debug mode is off, that VM migration is not permitted, and that
  side-channel mitigations are active;
- that firmware versions are not known-vulnerable ones;
- that the GPU is genuinely in confidential mode.

Most importantly: the report contains a digest of the enclave's public key. That
binding is what guarantees the decryption key is encrypted **for that specific
enclave**, and not for an intermediary relaying evidence obtained elsewhere.

### When the key is released

The key is never staged in advance: not in the system image, not in an
environment variable, not in a configuration file — all of these are readable by
the infrastructure administrator.

It is **requested by the enclave at the moment computation starts**, released
after verification, used, then erased when the virtual machine is destroyed. One
virtual machine per study: the window during which a key exists in memory is
measured in minutes.

Verification is not delegated to clinical workstations — that would require
maintaining manufacturer certificate chains and revocation lists on every one of
them. It is centralized in a dedicated service (a "key broker") that holds the
keys and releases them only after checking the evidence. Implementations exist
both in open source (Confidential Containers / Trustee) and from cloud vendors.

### The non-negotiable prerequisite

Attestation compares a measurement against an expected value — which requires
being able to compute that value. This demands a **reproducible build**, where
the same source always yields the same measurement, and signed publication of
those measurements for every release. Without it, attestation proves nothing,
for lack of a reference to compare against.

---

## 7. Limitations — what this system does not do

This section is deliberately explicit. A submission that does not state its
limits cannot be evaluated.

**Encryption is not de-identification.** Developed in section 2. All HIPAA and
GDPR obligations remain in force.

**The key is the critical point.** It is currently stored in the clear on the
clinical workstation, in a file readable only by its owner. Whoever obtains that
file obtains the data. Two consequences: offline backup is essential (losing it
makes studies permanently unreadable, with no recovery path), and protecting it
is a matter of workstation security, not of this system. A hardware security
module or a managed key service is the natural improvement.

**Metadata stripping must happen upstream.** Encryption faithfully preserves
whatever it is given, identifying metadata included. Cleaning DICOM headers
(name, date of birth, accession number, private tags, burned-in annotations)
must precede encryption.

**The clinical workstation is not protected.** Before encryption and after
decryption, the study sits in the clear on the user's machine. Workstation
security — full-disk encryption, session locking, patching — remains a
prerequisite.

**The enclave's trusted computing base is large.** An enclave contains a full
operating system and every library the program uses. A vulnerability in the
application server bypasses hardware protection entirely. Hence the requirement
for a minimal image and for code review.

**Trust in the manufacturer remains.** AMD, Intel and NVIDIA could, in theory,
extract keys from their own silicon; so could a court order. That is the
accepted trade-off of this technology: near-native computation speed in exchange
for trusting the vendor. Techniques that would remove this assumption
(homomorphic encryption) remain far out of reach performance-wise for 3D
imaging.

**Some side channels remain.** Memory contents are encrypted, but memory
*addresses* are not. A privileged observer could in principle infer information
from access patterns. For a dense neural network, those patterns are dictated by
model architecture rather than study content, which sharply limits the attack —
but it exists and belongs in the risk analysis.

**Attestation proves code identity, not code correctness.** It certifies that
the running program matches the published measurement. If that program contains
a flaw, or writes data where it should not, attestation will faithfully certify
it anyway. Code review remains necessary.

---

## 8. Regulatory positioning

Material for an IRB, HIPAA or GDPR submission. This does not substitute for
review by your privacy officer or IRB.

### Under HIPAA

**Nature of the data.** Imaging volumes containing facial anatomy are PHI.
Encryption does not change that classification, and encrypted PHI is still PHI.

**Security Rule.** Encryption at rest and in transit satisfies the addressable
implementation specifications at §164.312(a)(2)(iv) (encryption and decryption)
and §164.312(e)(2)(ii) (transmission security), using NIST-standardized
algorithms.

**Breach Notification Rule.** HHS guidance identifies encryption consistent with
NIST SP 800-111 as rendering PHI *unusable, unreadable, or indecipherable*.
Exposure of encrypted files, with keys uncompromised, therefore falls outside
the definition of a breach of unsecured PHI at §164.402 — case-by-case
confirmation with your privacy office is still required.

**De-identification.** This system makes no de-identification claim. If studies
are to be shared as de-identified, that must be established separately, through
Safe Harbor or Expert Determination. A Limited Data Set under a Data Use
Agreement may be the more practical route for multi-site work.

### Under GDPR

**Nature of the data.** Health data, special category (Art. 9). Encrypted data
whose key is held remains personal data (Art. 4(5), Recital 26).

**Technical measures (Art. 32).** Encryption at rest and in transit with
NIST-standardized algorithms; integrity guaranteed by authenticated encryption;
protection in use via hardware enclave with remote attestation (target
architecture, section 6).

**Data breach (Art. 34(3)(a)).** With data encrypted by a state-of-the-art
method and keys uncompromised, exposure of encrypted files may be assessed as
not presenting a high risk to individuals — to be confirmed case by case with
the Data Protection Officer.

### Clinical argument supporting this approach

Defacing causes loss of diagnostic information and introduces artifacts near
regions of interest. Encryption preserves the study in full. That preservation
is a defensible reason to adopt an alternative technical safeguard in a risk
analysis, and it is the strongest argument in favor of this architecture.

### Traceability

SHA-256 digests are retained for every study, allowing proof that no alteration
occurred between the clinical workstation and the returned result.

---

## 9. Glossary

**AES-256** — standardized encryption algorithm with a 256-bit key. A worldwide
standard, used among other things for classified information.

**Attestation** — a process by which a processor produces signed evidence of
what a machine is running, remotely verifiable by a third party.

**Authenticated encryption (GCM)** — an encryption mode guaranteeing both that
content is unreadable and that it has not been modified.

**Digest (hash, SHA-256)** — a short fingerprint computed from a file. Different
files produce different digests, allowing verification that a file has not
changed.

**Enclave / TEE** — a hardware-isolated execution environment whose memory is
encrypted by the processor and inaccessible to the host system.

**Entropy** — a measure of statistical disorder. A properly encrypted file
reaches the maximum value of 8 bits per byte, indicating no detectable
structure.

**Hypervisor** — the software managing virtual machines. On conventional
infrastructure it can read the memory of the machines it hosts; enclaves prevent
this.

**Key** — a 256-bit secret without which an encrypted file is unusable. Its loss
is irreversible.

**PHI** — Protected Health Information, as defined by HIPAA.

**Pseudonymization** — replacement of direct identifiers, reversible through a
mapping table. Remains personal data under GDPR.

---

## References

- FIPS 197 — *Advanced Encryption Standard*, NIST
- NIST SP 800-38D — *Galois/Counter Mode (GCM) and GMAC*
- NIST SP 800-111 — *Guide to Storage Encryption Technologies for End User Devices*
- 45 CFR §164.312, §164.402, §164.514 — HIPAA Security, Breach Notification and
  Privacy Rules
- Regulation (EU) 2016/679 (GDPR), Art. 4(5), 9, 32, 34 and Recital 26
- `conf_computing.md` — detailed technical note on confidential computing
  (hardware mechanisms, attestation protocol, limitations)
- `volume_crypto/README.md` and `volume_crypto/GUIDE_UTILISATION.md` — encryption
  tool documentation
- `SECURITE.md` — French version of this document
