# Development plan: from a demonstration to a verifiable pipeline

Written 2026-08-21 in `~/Projects/UNC/cryptography/volume_crypto/`.
Driver: the panel review of the integrated AMIA draft
(`~/Projects/UNC/research_writing/AMIA_conf_27/06_paper/reviews/review_v1_secure.md`).
Nothing here is implemented yet. This document is the plan; code follows once
it is agreed.

---

## 0. What the review actually said, in one place

Three findings drive every work package below. They are quoted so the plan
can be checked against them rather than against my summary of them.

**S1 (CRITICAL).** "The two halves of the title never meet in any experiment.
The confidentiality chain is measured on its own demo server with identity
processing. No encrypted study has ever traversed the tool server; no
segmentation has ever run behind the attestation gate."

**S2 (CRITICAL).** "The attestation measures 4 protocol files; the thing that
touches plaintext is the 26 GB of tool stacks. After key release the server
decrypts and hands the study to a tool venv that is outside the measurement.
The claim 'the server never holds a readable study without proving its code'
is therefore true only for a definition of 'its code' that excludes the code
that does the reading."

**S4 (MAJOR).** "946 MB/s upload and the 1.60 s round trip are one-machine
figures."

The Devil's Advocate added the framing that matters most: *"the threat model
excludes the only adversary that matters, the TCB excludes the only code that
matters."* The plan's job is to make both of those sentences false, or at
minimum to make their remaining truth explicit, bounded, and tested.

---

## 1. Goal

Turn a working demonstration into **a pipeline whose correctness a third party
can verify without reading the source**, and which grafts onto the real tool
server rather than living beside it.

Three claims are the deliverable. Each must end the project with a test that
fails if the claim stops holding:

1. **Confidentiality boundary.** Plaintext exists in exactly one place in the
   server, for a bounded interval, and nowhere else. Not "we were careful":
   an executable invariant.
2. **Conditional release.** The key reaches the server only after the client
   has verified evidence covering *everything that will touch the plaintext*,
   tool environments included.
3. **Real work.** A real dental imaging tool runs behind that gate, on a real
   CBCT, and its output is bit-identical to the same tool run in the clear.

Claim 3 is what closes S1. Claim 2 with "tool environments included" is what
closes S2. Claim 1 is the architectural property that makes both testable.

Non-goal, stated once: this project does not build hardware attestation, and
it does not claim to defeat a malicious operator. It builds the protocol and
the measurement surface that a hardware root of trust drops into, and it says
so everywhere.

---

## 2. What exists today, and why it does not carry the claims

`voltcrypt/` is sound and stays: `crypto.py` (AES-256-GCM, 4 MiB streaming,
per-block AAD, encrypted filename), `keys.py`, `batch.py`, `audit.py`,
`timing.py`, `attestation.py`, `keyexchange.py`. 3,481 lines total, 108 tests,
two commits dated 2026-08-14.

Three structural limits:

- **`server.py` is a 441-line monolith** in which the plaintext boundary is a
  `try` block inside `process_job` (server.py:143). The confidentiality claim
  is a property of that block's discipline, and discipline is not testable.
- **The "processing" is `output.write_bytes(content)`** (server.py:166). The
  identity function. It proves the chain moves bytes; it proves nothing about
  running a tool.
- **`MEASURED_FILES` is a four-element list** (server.py:57). It covers the
  protocol. It does not cover whatever the processing step imports, which in
  the real system is a per-tool virtualenv with its own torch.

---

## 3. Prior art, and where this sits

Searched 2026-08-21. Two families dominate privacy-preserving remote medical
inference, and both trade throughput for cryptographic strength:

- **Homomorphic encryption** (TFHE-based frameworks; CNN inference services
  for cloud medical imaging, 2025). Compute on ciphertext, no plaintext ever.
  Orders of magnitude too slow for a 512x512x365 CBCT, which our own profiling
  puts at 4.5 s of inference in the clear.
- **Secure multi-party computation**, notably **PriMIA** for encrypted medical
  image inference. Same conclusion at volume scale, plus a multi-party
  deployment requirement a dental clinic will not meet.

The third family is **attestation-gated execution**: keep symmetric encryption
(fast), and move the trust question to "what code is allowed to hold the key".
That is the confidential-computing route, and its production machinery is
exactly what our S2 fix needs:

- **dm-verity root hash over the container image**, as used by Confidential
  Containers and Kata policy generation: every image layer is hashed, and
  tampering is detected when layers are mounted. This is the industrial answer
  to "measure more than four files".
- **Reproducible builds** to make the measurement meaningful (a digest you
  cannot rebuild is a number, not a proof).
- **IMA** for runtime measurement where build-time measurement is not enough.

The positioning that follows, and it is the paper's argument too: HE and SMPC
protect the data from the compute; attestation protects the data from the
*operator of* the compute, at a cost that a 3D imaging workload can pay. Our
contribution is not a new primitive. It is the first end-to-end instance of
the attestation-gated route in dental imaging, with the measurement surface
extended to the per-tool environments that the isolation architecture makes
enumerable in the first place.

That last clause matters and should be said plainly: **per-tool isolation was
built for dependency conflicts, and it turns out to be what makes the TCB
enumerable.** One `uv.lock` per tool is a manifest. The build-time dedup
invariant already fails the image when the tool set changes unexpectedly. The
access architecture and the privacy architecture are the same architecture.

---

## 4. Target architecture

Still small. The point is not more machinery; it is that the confidentiality
claim becomes a property of the module graph.

```
volume_crypto/
  voltcrypt/                  unchanged core primitives
    crypto.py  keys.py  batch.py  audit.py  timing.py
    keyexchange.py
    attest/
      evidence.py             produce / verify (today's attestation.py, split)
      measure.py              NEW: the measurement surface, see 4.2
      roots/
        software.py           Ed25519 on disk, today's behaviour, labelled
        hardware.py           NEW: stub with the SEV-SNP / TDX call sites
  cryptoserve/                NEW: the small server, replaces server.py
    app.py                    HTTP routes only, no crypto, no plaintext
    jobs.py                   job store + explicit state machine
    enclave.py                key custody, ephemeral keys, zeroisation
    boundary.py               THE plaintext boundary. The only module allowed
                              to hold cleartext. ~80 lines.
    runners/
      identity.py             today's behaviour, kept as the control arm
      subprocess_tool.py      NEW: runs a real tool in its own venv
  cryptoverify/               NEW: the conformance harness, see section 6
  tests/
    conformance/  properties/  protocol/  adversary/  bench/
  evidence/                   machine-readable test output, see section 7
```

### 4.1 The boundary module is the whole design

`boundary.py` is the only module that ever holds a decrypted byte. Everything
else moves ciphertext. It has one public function, roughly:

```python
def process(job, key, runner) -> ResultRef:
    """Decrypt, run, re-encrypt. Plaintext lives only inside this call."""
```

Why this shape and not a tidier one: it makes the confidentiality claim
**checkable by import graph**. A test walks the module graph of `cryptoserve`
and asserts that no module other than `boundary` imports the decryption
entry points, and that `app.py` and `jobs.py` never receive a plaintext path.
The claim "the server cannot read this" stops being a promise about behaviour
and becomes a statement about which code can even express the operation.

The boundary also owns the hygiene that the review flagged: a working
directory on a tmpfs (not the job disk), unlinked before return on every path
including failure, key held in a single reference released immediately after
re-encryption, and a recorded plaintext residency duration that becomes a
reported number rather than an assurance.

### 4.2 The measurement surface, which is the S2 fix

`measure.py` produces one digest over an explicit, ordered manifest:

| Component | What is hashed | Why |
|---|---|---|
| Protocol | `app.py`, `boundary.py`, `enclave.py`, `evidence.py`, `keyexchange.py`, `crypto.py` | today's four, plus the two that actually move plaintext |
| Runner | the active runner module | the code that invokes the tool |
| Tool environment | per tool: `uv.lock` digest + a tree digest of the installed venv | **the code that reads the plaintext** |
| Interpreter | Python build identity per venv | a different interpreter is a different TCB |
| Policy | the declared policy dict | so policy cannot drift silently from evidence |

Two tests make this honest rather than decorative:

- changing **any** manifest entry changes the digest (parametrised over the
  manifest, so a new entry is covered the day it is added);
- changing a file **outside** the manifest does *not* change it. This test is
  the executable definition of the TCB, and its list of accepted exclusions
  (OS, kernel, CUDA driver, hardware) is what the paper prints.

The tree digest of a venv is expensive on 26 GB. Two mitigations, both worth
measuring rather than assuming: hash the `uv.lock` plus the venv's file
inventory (names, sizes, modes) rather than contents by default, and offer
full-content mode for a release; and cache per tool keyed on the lock digest.
Report both cost and coverage; a cheap digest that a reviewer can see through
is worse than an expensive one honestly labelled.

### 4.3 Runners, and the graft

`runners/identity.py` keeps today's behaviour as the **control arm**. It is
not dead code: the paper needs an identity baseline to separate protocol cost
from tool cost.

`runners/subprocess_tool.py` is the graft. It executes exactly what the real
server executes:

```
<TOOLS_DIR>/<tool>/.venv/bin/python <RUNNER_PATH> --job <job dir>/job.json
```

This is the contract already implemented in `slicer-remote-tool-server`
(`server/execution/runner.py`), and reusing it verbatim is the point: the
graft is a *substitution of the processing step*, not a parallel
implementation. In the real server, `process_job`'s equivalent is the
dispatch path; the confidentiality layer wraps it by decrypting into the job
directory before dispatch and encrypting the outputs after.

---

## 5. Work packages

Each package states its acceptance test. A package is done when its test
passes in CI, not when the code runs on my machine.

### WP1. Split the monolith, establish the boundary
Extract `server.py` into `cryptoserve/`. Behaviour identical, identity runner
active. Job states become an explicit enum with a transition table.

*Accept:* the existing 28 pipeline tests pass unchanged against the new
package; the import-graph test passes (only `boundary` can decrypt); plaintext
residency is measured and reported per job.

### WP2. Extend the measurement surface
Implement `measure.py` per 4.2, with the manifest, the caching, and the two
honesty tests. Keep `roots/software.py` as the signer and add
`roots/hardware.py` with the real ioctl call sites documented and raising
`NotImplementedError`, so the substitution point is visible in the code rather
than only in a docstring.

*Accept:* manifest-change and non-manifest-change tests pass; the TCB
inclusion/exclusion list is generated from code into
`evidence/measurement.json`; a modified tool venv changes the digest and the
client refuses the key.

### WP3. Run one real tool behind the gate
Implement `runners/subprocess_tool.py`. Target tool: **AMASSS** (parity closed,
GPU, the dominant workload). Fallback if the GPU box is unavailable:
**Crown_Seg** or the `_dispatch_probe` fixture, in that order.

*Accept:* on one real de-identified CBCT, the tool runs behind the attestation
gate and its output is **bit-identical** to the same tool run in the clear on
the same input. This single assertion is what closes S1, and it should be the
first test written, before the code that makes it pass.

### WP4. Real network numbers
Replace loopback measurement with a characterised two-host setup: LAN, plus a
throttled clinic-representative uplink shaped with `tc`/`netem`, both
directions measured and recorded. Include an induced mid-transfer failure to
exercise resumption.

*Accept:* `evidence/bench.json` carries size, wall clock, throughput, host
pair, RTT, shaped bandwidth, and commit, for every reported figure. No number
reaches the paper without a network condition attached (S4).

### WP5. The conformance harness
See section 6. This is the deliverable the user asked for: a thing that checks
the pipeline is respected.

*Accept:* `cryptoverify` run against a deliberately broken server (five
seeded defects) reports all five; run against the good server, reports clean;
emits `evidence/adversary.json`.

### WP6. Hygiene debts named in PIPELINE.md
TLS terminated inside the boundary process, client authentication, a distinct
client-supplied return key so the server never reuses the input key, and a
purge for `server_storage`. These are the review's smaller flanks; they are
cheap and they remove easy objections.

*Accept:* each has a test; the demo runs over TLS; results encrypt under a
return key the server never chose.

---

## 6. `cryptoverify`: proving the pipeline is respected

The core idea, and the piece most worth building: **a checker that treats the
server as a black box and decides whether the confidentiality claim holds.**
It grafts onto any deployment, including the real tool server once WP3 lands.

It runs a fixed battery and emits a verdict:

1. **Canary submission.** Submit a volume containing a high-entropy marker and
   a recognisable patient-name string. Assert the marker and the name appear
   nowhere in anything the server stores or returns before key release, and
   nowhere in the result after (a re-encrypted result must not leak either).
2. **Refusal battery.** The five protocol attacks already covered by tests,
   plus: modified measurement, modified tool venv, stale nonce, substituted
   ephemeral key, key replayed on another job. For each, assert not just an
   error but that **the key did not move** and **no plaintext artifact was
   created**.
3. **Ordering battery.** Key before job, result before key, key twice, result
   twice, job id from another session. Each must leave state unchanged.
4. **Residency probe.** Measure how long plaintext exists and assert it is
   bounded; assert the working directory is gone afterwards on both the
   success and the failure path.
5. **Measurement audit.** Fetch the advertised measurement, recompute it from
   a local checkout at the claimed commit, and report agreement or divergence.
   This is what lets a *site* verify a deployment it did not build.

Output is `evidence/adversary.json` plus a one-page human report. The value is
that this same harness runs against the demo server today and against the
production tool server later, so the claim is not re-argued, it is re-run.

---

## 7. Test strategy

Following the `crypto-pipeline-testing` skill written for this work
(`~/.claude/skills/crypto-pipeline-testing/`). Four layers, in order:

**Layer 1, primitive conformance.** Wycheproof vectors for AES-GCM
(`aes_gcm_test.json`, 44 groups, 316 vectors), X25519, Ed25519, HKDF-SHA256,
cloned in CI. Assert on the vector `flags`, not merely raise/no-raise. Plus an
explicit nonce-uniqueness test and per-field AAD binding tests.

**Layer 2, properties** (`hypothesis`). Round trip over generated sizes
including every buffer boundary; wrong key; tamper by region (header, payload,
tag, length prefix) so a failure says *where*; truncation; reorder, splice,
duplicate; no-plaintext-leakage including the filename. Each property named
for the claim it defends.

**Layer 3, protocol state machine** (`RuleBasedStateMachine`). States and
transitions modelled explicitly; invariants that must hold in every reachable
state: the key never appears in bytes written to disk, no result exists before
key release, out-of-order requests leave state unchanged with no partial
artifact.

**Layer 4, adversary tests.** One test per named attack, the test name *is*
the attack, and each asserts the negative outcome as state.

Current suite: 108 tests. Target after WP1 to WP5: the same tests plus the
four layers, all runnable with **no GPU, no weights, no network**, except one
clearly marked slow lane for WP3's real-tool parity and WP4's two-host
benchmarks.

---

## 8. Evidence artifacts, mapped to paper claims

Every number in the paper gets a file that regenerates it.

| Artifact | Feeds |
|---|---|
| `evidence/vectors.json` | primitive conformance statement in Methods |
| `evidence/properties.json` | container-format guarantees (AAD, truncation, splice) |
| `evidence/protocol.json` | state-machine coverage |
| `evidence/adversary.json` | the attack table in Table 4 |
| `evidence/bench.json` | throughput and round-trip numbers, with network condition (S4) |
| `evidence/measurement.json` | **the TCB table: what is measured, what is excluded (S2)** |
| `evidence/parity_encrypted.json` | **bit-identical tool output through the chain (S1)** |

The last two are the ones that change the paper's verdict.

---

## 9. Sequence, against the 3 September deadline

Today is 21 August. Thirteen days. The paper needs S1 and S2 closed; the rest
strengthens the project beyond this cycle.

| Days | Work | Paper consequence |
|---|---|---|
| 1 to 2 | WP1 split + boundary + import-graph test | nothing visible yet, everything rests on it |
| 2 to 4 | **WP3 parity test first, then the runner** | closes S1: "one real tool through the attested chain" |
| 4 to 6 | WP2 measurement surface + TCB tests | closes S2: the TCB table becomes printable |
| 5 to 7 | WP4 two-host benchmarks (parallel, needs the second machine) | closes S4 |
| 7 to 9 | WP5 `cryptoverify` + Layer 4 adversary tests | upgrades Table 4 from "tests exist" to "run it yourself" |
| 9 to 11 | Layers 1 to 3, evidence artifacts | Methods rigor paragraph |
| 11 to 13 | WP6 hygiene, docs, freeze commits, Zenodo | submission gate |

**Hard decision point, day 4.** If WP3's parity assertion is not passing by
then, stop and take the review's option (b): soften the paper's title and
conclusion, publish the confidentiality layer as a measured component with
integration designed, and keep the full claim for the follow-on. Do not spend
days 5 to 13 chasing S1 at the cost of S2 and S4, which are cheaper and also
required.

---

## 10. Risks

| Risk | Move |
|---|---|
| GPU box unavailable for WP3 | fall back to Crown_Seg, then `_dispatch_probe`; the parity claim holds for whichever tool ran, and the paper names it |
| Venv tree digest too slow on 26 GB | lock-digest + inventory mode by default, full-content for releases, both timed and reported |
| Real tool is nondeterministic (nnU-Net CUDA) | reuse the existing parity protocol's tolerance definition; do not invent a second standard |
| `tc`/`netem` needs privileges on the clinic-representative host | shape on the sender side in a namespace, or report LAN only and say so |
| The refactor destabilises the 108 passing tests | WP1 accept criterion is those tests passing unchanged; if they need edits, the edits are reviewed as a separate commit |
| Scope creep into hardware attestation | `roots/hardware.py` raises `NotImplementedError` on purpose; that boundary is the plan, not a shortfall |

---

## 11. What I need before starting

1. Green light on the architecture in section 4, in particular the
   `boundary.py` shape, since WP1 rewrites the server around it.
2. Which tool for WP3, and whether the GPU machine is available in the window.
3. The second host for WP4, with its network path to the server.
4. Confirmation that `slicer-remote-tool-server` can be checked out beside
   this project so `subprocess_tool.py` can reuse the real runner contract
   rather than reimplement it.
