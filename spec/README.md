# Verifiable Intent (VI) — Specification Overview

**Version**: 0.1-draft
**Status**: Draft
**Date**: 2026-02-18
**Authors**: Verifiable Intent Working Group

## Abstract

Verifiable Intent (VI) defines a layered SD-JWT credential format
that creates a cryptographically verifiable chain binding an AI agent's
commercial actions to an end-user's explicitly stated purchase intent. The
format supports two execution modes — Immediate (user-confirmed) and
Autonomous (agent-delegated) — using selective disclosures to ensure each
party in a transaction sees only the claims relevant to its role.

This document specifies the VI architecture, trust model, selective disclosure
model, and conformance requirements. For the normative credential format,
see [credential-format.md](credential-format.md). For constraint type
definitions and validation rules, see [constraints.md](constraints.md).

### Companion Documents

| Document | Description |
|----------|-------------|
| [credential-format.md](credential-format.md) | Normative credential format, claim tables, and serialization |
| [constraints.md](constraints.md) | Constraint type definitions and validation rules |
| [security-model.md](security-model.md) | Threat model and security analysis |
| [design-rationale.md](design-rationale.md) | Why SD-JWT, relationship to OpenID4VP/FIDO2/SCA, algorithm choice |
| [glossary.md](../protocol-landscape/glossary.md) | Full glossary with protocol-specific mappings |

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174]
when, and only when, they appear in ALL CAPITALS, as shown here.

The following notation is used throughout this specification:

- JSON structures are represented in JSON [RFC 8259] notation.
- Base64url encoding refers to the encoding defined in [RFC 4648], Section 5,
  without padding characters.
- `B64U(x)` denotes the base64url encoding of the byte string `x`.
- `SHA-256(x)` denotes the SHA-256 hash [FIPS 180-4] of the byte string `x`.
- `ASCII(x)` denotes the ASCII encoding of the string `x`.
- SD-JWT notation follows [RFC 9901].

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Issuer** | Entity that creates and signs the L1 credential. Either a financial institution (bank) that issued the user's payment card, or a payment network (Mastercard) acting on the bank's behalf. Responsible for user identity verification and L1 signing. Issues L1 into a Credential Provider's wallet. The VI Issuer role (signing L1) is distinct from the payment card issuer role (underwriting the account), even when the same entity fills both. |
| **Credential Provider** | Entity that hosts the wallet infrastructure where L1 credentials are stored and where users create L2 credentials. Examples include digital wallet providers and payment platforms. The Credential Provider provides the wallet; the Issuer signs the credentials that go into it. Distinct from the Issuer, which creates and signs L1.|
| **User** | End-user (the delegating principal) who creates Layer 2 mandates expressing purchase intent. The user is the ultimate authority in the delegation chain. In protocol descriptions, "the user creates L2" refers to any authorized system holding the user's private key — see [security-model.md §3.5](security-model.md#35-deployment-models). |
| **Agent** | AI-powered software that acts on behalf of the user. In Autonomous mode, the agent creates Layer 3 mandates fulfilling user constraints. |
| **Merchant** | Entity that sells goods or services. The merchant creates signed checkout JWTs and processes checkout requests. |
| **Payment Network** | Entity that routes and settles payment transactions. Validates the VI credential chain as a pre-authorization step during transaction routing. |
| **Verifier** | Any party that validates a VI credential chain. Merchants and payment networks are the primary verifiers. |
| **SD-JWT** | Selective Disclosure JWT as defined in RFC 9901. A JWT that supports selective disclosure of claims using hash-based commitments. Uses the combined format: `<JWT>~<Disclosure 1>~<Disclosure 2>~...~` |
| **KB-SD-JWT** | Key-Bound SD-JWT. An SD-JWT that proves key binding through: (1) an `sd_hash` claim binding it to a prior layer credential, (2) a signature created with a private key matching the public key in the prior layer's `cnf.jwk` claim, and (3) a `kid` header parameter that verifiers match against the prior layer's `cnf.kid` to resolve the signing key. L3a and L3b use this format (`typ: "kb-sd-jwt"`). |
| **KB-SD-JWT+KB** | Key-Bound SD-JWT with Key Binding for further delegation. Extends KB-SD-JWT by including a `cnf.jwk` claim in the payload to enable the next layer of delegation. L2 uses this format in Autonomous mode (`typ: "kb-sd-jwt+kb"`). The "+kb" suffix indicates the credential carries key binding for onward delegation. |
| **Layer 1 (L1)** | The Credential Provider SD-JWT. Binds the user's identity and public key via `cnf.jwk`. Does not contain `sd_hash` (it's the root credential). Long-lived (~1 year). |
| **Layer 2 (L2)** | The User KB-SD-JWT or KB-SD-JWT+KB. Contains mandates expressing the user's purchase intent — either final values (Immediate mode, `typ: "kb-sd-jwt"`) or constraints (Autonomous mode, `typ: "kb-sd-jwt+kb"`). Contains `sd_hash` binding to L1. In Autonomous mode, includes `cnf.jwk` in mandates to bind the agent's key for L3 delegation. |
| **Layer 3 (L3)** | The Agent KB-SD-JWT(s) (Autonomous mode only). In Autonomous mode, L3 splits into two KB-SD-JWT credentials: L3a (payment mandate, sent to the payment network) and L3b (checkout mandate, sent to the merchant). Each contains the agent's fulfillment of user constraints with concrete purchase values. Contains `sd_hash` binding to L2 + relevant disclosures. Short-lived (~5 minutes). `typ: "kb-sd-jwt"` |
| **Mandate** | A selectively disclosable claim within a KB-SD-JWT that expresses intent for a specific aspect of a transaction (checkout or payment). |
| **Checkout Mandate** | A mandate with `vct: "mandate.checkout.open"` (Autonomous L2) or `vct: "mandate.checkout"` (Immediate L2 / L3b) that describes allowed or finalized checkout contents. |
| **Payment Mandate** | A mandate with `vct: "mandate.payment.open"` (Autonomous L2) or `vct: "mandate.payment"` (Immediate L2 / L3a) that describes allowed or finalized payment parameters. |
| **Mandate Pair** | A checkout mandate and its corresponding payment mandate within the same L2, linked by `checkout_hash` binding (Immediate) or `conditional_transaction_id` in `payment.reference` constraint (Autonomous). In v0.1, each mandate pair represents a single authorized transaction — exactly one L3a + L3b pair (Autonomous) or a final transaction record (Immediate). A future extension for multi-transaction mandate pairs will likely allow multiple L3 fulfillments per pair within defined bounds. |
| **Constraint** | A typed rule within an Autonomous mode mandate that bounds the agent's authority (e.g., budget limit, allowed SKUs, approved merchants). |
| **Delegation Chain** | The sequence of cryptographic bindings (L1 → L2 → L3) where each layer's signing key is bound by the `cnf` claim of the previous layer. |
| **Disclosure** | A base64url-encoded JSON array containing a salt and a claim value, used for selective disclosure per [RFC 9901]. |
| **`sd_hash`** | A SHA-256 hash binding each layer to the serialized form of the previous layer. Ensures that the serialized prior credential as received by the signer has not been modified. See §3.2. |
| **`cnf` (Confirmation)** | A claim defined in [RFC 7800] that binds a JWT to a specific cryptographic key. VI uses `cnf` claims at each delegation layer to create the authorization chain. L1 contains `cnf.jwk` binding the user's key. L2 mandates contain `cnf.kid` and `cnf.jwk` binding the agent's key (Autonomous mode only). L3 does not contain `cnf` (terminal delegation); the agent's key is resolved from L2 via `kid` matching. |
| **`checkout_hash`** | A SHA-256 hash of the `checkout_jwt` string, binding checkout and payment mandates. Checkout mandates carry this hash as `checkout_hash`; payment mandates carry the same hash as `transaction_id`. In Autonomous mode, L3a (`transaction_id`) and L3b (`checkout_hash`) cross-reference the split L3 credentials. |
| **`delegate_payload`** | An array of SD-JWT disclosure references (`{"...": "<hash>"}`) in the KB-SD-JWT payload that point to the selectively disclosable mandate claims. |
| **Fulfillment** | The concrete values in an L3 mandate that satisfy the constraints from the corresponding L2 mandate. For example, a specific merchant selection that satisfies an `allowed_merchant` constraint. |
| **Split L3** | The pair of L3 credentials in Autonomous mode: L3a (payment mandate, sent to the payment network) and L3b (checkout mandate, sent to the merchant). Each contains a selective `sd_hash` over only the L2 disclosures its recipient sees. |
| **Network-Enforced Constraint** | A constraint type whose enforcement requires state tracking across multiple transactions. Includes `payment.budget`, `payment.recurrence`, and `payment.agent_recurrence`. These cannot be verified by a stateless verifier — the payment network maintains cumulative state. |
| **Immediate Mode** | A 2-layer execution mode (L1 + L2) where the user directly confirms final transaction values. No agent delegation occurs. L2 uses `typ: "kb-sd-jwt"`. |
| **Autonomous Mode** | A 3-layer execution mode (L1 + L2 + L3) where the user delegates authority to an agent within cryptographically bound constraints. L2 uses `typ: "kb-sd-jwt+kb"` to enable L3 delegation. L3a and L3b use `typ: "kb-sd-jwt"`. |

---

## 3. Architecture Overview

### 3.1 Layered Credential Architecture

VI uses a layered credential architecture where each layer builds on the
previous one through cryptographic key binding. The number of layers determines
the execution mode.

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1 — SD-JWT                         │
│              Credential Provider → User                     │
│                                                             │
│  Identity claims (email), pan_last_four, scheme             │
│  cnf.jwk = User Public Key                                  │
│  NO sd_hash (root credential)                               │
│  Lifetime: ~1 year                                          │
│  Signed by: Credential Provider private key                 │
└───────────────────────────┬─────────────────────────────────┘
                            │ L2 signed by key in L1 cnf.jwk
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  LAYER 2 — KB-SD-JWT / KB-SD-JWT+KB         │
│                  User → Agent / Verifier                    │
│                                                             │
│  IMMEDIATE MODE             │  AUTONOMOUS MODE              │
│  ─────────────              │  ───────────────              │
│  typ: "kb-sd-jwt"           │  typ: "kb-sd-jwt+kb"          │
│  Final checkout (checkout_jwt)│ Checkout constraints        │
│  Final payment values       │  Payment constraints          │
│  NO cnf in mandates         │  cnf.kid+jwk = Agent Key in mandates│
│  sd_hash = hash(L1)         │  sd_hash = hash(L1)           │
│  Lifetime: ~15 minutes      │  Lifetime: 24 hours – 30 days │
│  Signed by: User Public Key │  Signed by: User Public Key   │
└─────────────────────────────┼───────────────────────────────┘
                              │ L3 signed by key in L2
                              │ mandate cnf.jwk
                              ▼ (Autonomous only)
┌─────────────────────────────────────────────────────────────┐
│            LAYER 3 — Split KB-SD-JWTs                       │
│             (Autonomous mode only)                          │
│             typ: "kb-sd-jwt"                                │
│                                                             │
│  L3a (Payment → Network)    │  L3b (Checkout → Merchant)    │
│  ─────────────────────────  │  ──────────────────────────   │
│  Final payment values       │  Final checkout (checkout_jwt)│
│  transaction_id             │  checkout_hash                │
│  payment_instrument         │  line_items                   │
│  NO cnf (terminal)          │  NO cnf (terminal)            │
│  sd_hash = hash(L2 + disclosures) │  sd_hash = hash(L2 + disclosures) │
│  header.kid = Agent Key ID   │  header.kid = Agent Key ID     │
│                                                             │
│  Cross-reference: L3a transaction_id == L3b checkout_hash   │
│  Lifetime: ~5 minutes                                       │
│  Signed by: Agent private key                               │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Delegation Chain

The delegation chain is the core security mechanism of VI. Each layer
cryptographically binds the next layer's signing authority through the `cnf`
(confirmation) claim defined in [RFC 7800].

**Normative requirements:**

1. The Layer 1 `cnf.jwk` claim MUST contain the user's public key.
   Layer 2 MUST be signed by the corresponding private key.

2. In Autonomous mode, each Layer 2 mandate `cnf` claim MUST contain `jwk` with
   the agent's public key and `kid` with a key identifier. Layer 3 MUST be signed
   by the corresponding private key.

3. In Immediate mode, Layer 2 mandates MUST NOT contain a `cnf` claim.
   The absence of `cnf` signals that no further delegation is permitted.

4. Each Layer 3 JWT header MUST contain a `kid` parameter matching L2 `cnf.kid`.
   Verifiers resolve the agent's public key from L2 `cnf.jwk` by matching
   `kid` values. L3 headers MUST NOT contain a `jwk` parameter.

5. Layer 3 credentials MUST NOT contain a `cnf` claim in the payload (terminal delegation).

6. For L2, `sd_hash` MUST equal
   `B64U(SHA-256(ASCII(serialized_L1)))`, binding it to the complete serialized
   form of L1. For each split L3, `sd_hash` MUST be computed over the L2 base
   JWT concatenated with only the disclosures relevant to that L3 (selective
   binding): L3a hashes L2 base + payment disclosure + merchant disclosure;
   L3b hashes L2 base + checkout disclosure + item disclosure.

> Note: The selective `sd_hash` in split L3 preserves the privacy boundary —
> L3a does not need to include checkout disclosures, and L3b does not need to
> include payment disclosures. The verifier recomputes `sd_hash` using the same
> selective approach per L3 type.

**Delegation chain summary:**

```
L1 cnf.jwk = User Public Key      ← Credential Provider binds user's key
L1 typ: "sd+jwt"                  ← Standard SD-JWT

L2 signed by User Public Key      ← Proves user created L2
L2 sd_hash = hash(L1)             ← Binds L2 to L1
L2 typ: "kb-sd-jwt+kb" (Autonomous) or "kb-sd-jwt" (Immediate)
L2 mandate cnf.kid + cnf.jwk = Agent Key  ← User binds agent's key (Autonomous only)

L3 signed by Agent Key            ← Proves agent created L3
L3 sd_hash = hash(L2 + disclosures) ← Binds L3 to specific L2 choices
L3 typ: "kb-sd-jwt"               ← KB-SD-JWT without onward delegation
L3 header kid = Agent Key ID      ← Verifier resolves key from L2 cnf.jwk via kid match
L3 NO cnf in payload              ← Terminal delegation, no further key binding
```

### 3.3 Two Execution Modes

VI supports two execution modes that differ in the number of credential layers
and the nature of the user's mandates.

| Aspect | Immediate Mode | Autonomous Mode |
|--------|----------------|-----------------|
| **Layers** | 2 (L1 + L2) | 3 (L1 + L2 + L3) |
| **Human presence** | User reviews and confirms final values | User sets constraints; agent acts independently |
| **L2 mandate content** | Final checkout JWT, final payment values | Constraints (amount range, line items, payees) + agent key binding |
| **`cnf` in L2 mandates** | Absent — no delegation | Present — binds agent's public key |
| **L2 `typ` header** | `kb-sd-jwt` | `kb-sd-jwt+kb` |
| **L3 `typ` header** | N/A (no L3) | `kb-sd-jwt` |
| **Agent role** | Forwarding only (no L3 creation) | Selects products, creates checkout, builds L3a + L3b |
| **Constraint checking** | Not applicable — values are final | Verifier checks L3 values against **disclosed** L2 constraints |

### 3.4 Mandate Types

Each Layer 2 (and Layer 3) credential contains mandates — selectively
disclosable claims that express specific aspects of the transaction intent.
VI defines two mandate types:

**Checkout Mandate** (`vct: "mandate.checkout.open"` in Autonomous L2, `vct: "mandate.checkout"` in Immediate L2 / L3b):

Describes what is being purchased. In Immediate mode, contains the finalized
merchant-signed `checkout_jwt`. In Autonomous mode L2, contains constraints on allowed
products (line items, quantities, allowed merchants) and the agent's `cnf` (`kid` + `jwk`) for delegation. In L3b, contains the finalized `checkout_jwt` and `checkout_hash`.

**Payment Mandate** (`vct: "mandate.payment.open"` in Autonomous L2, `vct: "mandate.payment"` in Immediate L2 / L3a):

Describes how the purchase is funded. In Immediate mode, contains finalized
payment details (`payment_instrument`, `currency`, `amount`, `payee`, `transaction_id`, etc.). In
Autonomous mode L2, contains constraints on allowed payment parameters (amount range,
approved payees, `payment_instrument`) and the agent's `cnf` (`kid` + `jwk`). In L3a, contains the finalized payment values and `transaction_id`.

Both mandate types are delivered as selectively disclosable array elements
within the `delegate_payload` structure. This allows the checkout mandate to be
disclosed to the merchant while the payment mandate remains hidden (and vice
versa for the payment network).

**Mandate Pairs and Transaction Scope:**

An L2 credential contains one or more mandate pairs — each consisting of a
checkout mandate and its corresponding payment mandate, linked by `checkout_hash`
binding ([credential-format.md](credential-format.md) §6.2). Each mandate pair
represents a single authorized transaction: in Autonomous mode, the agent is
expected to produce exactly one L3a + L3b pair per mandate pair. Payment networks MUST
enforce this expectation by tracking L3 issuance per L2 mandate pair (see
[security-model.md §4.2](security-model.md#42-cross-merchant-replay)). This
rule applies unconditionally in the base model, including for mandate pairs with a
`payment.recurrence` constraint — this constraint defines the terms of a subscription
setup (one L3 pair establishes the subscription), not a count of L3s. When a
`payment.agent_recurrence` constraint is present, multiple L3 pairs are explicitly
authorized within defined bounds (see [constraints.md](constraints.md) §4.7).

Implementations MUST group checkout and payment mandates into pairs by matching
`checkout_hash` (Immediate mode) or `conditional_transaction_id` (Autonomous
mode). Verifiers MUST reject L2 credentials containing orphaned mandates (a
checkout with no matching payment or vice versa) or duplicate mandates sharing
the same pair identifier.

In the base model, one mandate pair maps to exactly one L3 pair. The
`payment.agent_recurrence` constraint enables **multi-transaction mandate pairs**
where a single mandate pair authorizes multiple L3 fulfillments within defined
bounds (occurrence cap, cumulative budget via `payment.budget`, date range).
See [constraints.md](constraints.md) §4.7 and [security-model.md §4.2](security-model.md#42-cross-merchant-replay).

---

## 4. Selective Disclosure Model

### 4.1 Philosophy

In a typical purchase transaction, the merchant needs to know what is being
bought but not how it is being paid for. The payment network needs to know the
payment details but not the specific items in the checkout. The user's email and
identity are needed by the credential provider but may be unnecessary for the
merchant or network.

VI uses SD-JWT's selective disclosure mechanism to segregate these boundaries.
Undisclosed claims remain cryptographically hidden; each party receives only the
mandates relevant to its role.

### 4.2 Disclosure Layers

**Layer 1 — Credential Provider SD-JWT:**

| Claim | Always Visible | Selectively Disclosable |
|-------|:--------------:|:-----------------------:|
| `iss`, `sub`, `iat`, `exp`, `vct` | Yes | — |
| `cnf.jwk` | Yes | — |
| `pan_last_four` | Yes | — |
| `scheme` | Yes | — |
| `card_id` (when present) | Yes | — |
| `email` | — | Yes |

The always-visible claims establish the credential's provenance, key binding,
and card identification (`pan_last_four`, `scheme`). The `email` claim is
selectively disclosable and disclosed only when needed for user identity
verification.

**Layer 2 — User KB-SD-JWT / KB-SD-JWT+KB:**

| Claim | Always Visible | Selectively Disclosable |
|-------|:--------------:|:-----------------------:|
| `nonce`, `aud`, `iat`, `sd_hash` | Yes | — |
| `delegate_payload` (references) | Yes | — |
| `prompt_summary` (Autonomous only) | — | Yes |
| Checkout mandate (full object) | — | Yes |
| Payment mandate (full object) | — | Yes |

Mandates are disclosed selectively — the checkout mandate is typically disclosed
to the merchant, while the payment mandate is disclosed to the payment network.
The `prompt_summary` provides a human-readable description of the user's intent.

**Layer 2 — Autonomous Mode Nested Disclosures:**

In Autonomous mode, individual merchants in the `mandate.checkout.allowed_merchant` constraint and
individual items in the `mandate.checkout.line_items` constraint are
themselves selectively disclosable. Each entry is a separate disclosure,
and the constraint references them by hash. This allows the
agent to disclose only the selected merchant or item to the verifier.

**Layer 3a — Agent Payment KB-SD-JWT (Autonomous only, sent to network):**

| Claim | Always Visible | Selectively Disclosable |
|-------|:--------------:|:-----------------------:|
| `nonce`, `aud`, `iat`, `sd_hash` | Yes | — |
| `delegate_payload` (references) | Yes | — |
| `header.kid` (agent key identifier) | Yes | — |
| Final payment mandate | — | Yes |
| Selected merchant | — | Yes |

**Layer 3b — Agent Checkout KB-SD-JWT (Autonomous only, sent to merchant):**

| Claim | Always Visible | Selectively Disclosable |
|-------|:--------------:|:-----------------------:|
| `nonce`, `aud`, `iat`, `sd_hash` | Yes | — |
| `delegate_payload` (references) | Yes | — |
| `header.kid` (agent key identifier) | Yes | — |
| Final checkout mandate | — | Yes |

### 4.3 Presentation Patterns

The following presentation patterns represent the RECOMMENDED disclosure
strategy for a standard purchase transaction:

**Merchant presentation** (checkout verification):

Disclose from L2 (or L3b in Autonomous mode):
- Checkout mandate (product details, merchant-signed checkout JWT)
- `prompt_summary` (optional — for audit trail)

Do NOT disclose:
- Payment mandate (payment credentials, amounts)

**Payment network presentation** (payment authorization):

Disclose from L2 (or L3a in Autonomous mode):
- Payment mandate (payment credentials, amount, payee)
- Selected merchant (in Autonomous mode, disclosed within L3a)

Do NOT disclose:
- Checkout mandate (specific product details)

**Full-chain verification** (dispute resolution):

Disclose all mandates from all layers. This is an exceptional case used for
investigating disputed transactions. See [security-model.md](security-model.md)
§2.5 for the evidence elements and verification procedure available to dispute
investigators.

---

## 5. Trust Model

### 5.1 Roles

| Role | Trust Level | Responsibilities |
|------|-------------|------------------|
| **Issuer** | Trusted third party | Creates and signs L1 credentials; maintains user identity binding; provides JWKS endpoint for key discovery |
| **Credential Provider** | Service provider | Hosts wallet infrastructure; stores L1 credentials; enables L2 construction |
| **User** | Root of authority | Creates L2 mandates; defines all constraints and permissions; sole authority over the private key bound in L1 cnf.jwk |
| **Agent** | Constrained delegate | Creates L3 mandates within L2 constraints; MUST NOT exceed delegated authority; key is bound by L2 `cnf` |
| **Merchant** | Verifier | Creates signed checkout JWTs; verifies checkout mandate integrity; requests payment authorization |
| **Payment Network** | Verifier + Arbiter | Verifies full credential chain; checks constraints; routes authorization request; maintains audit trail |

> **Note:** The Payment Network validates the VI credential chain as a pre-authorization step. The final authorization decision rests with the issuing institution.

### 5.2 Trust Assumptions

1. **Credential Provider key integrity**: The Credential Provider's signing key
   is assumed to be securely managed (e.g., in an HSM). Compromise of this key
   undermines all credentials it has issued.

2. **User key integrity**: The user's private key is assumed to be protected by
   appropriate key protection infrastructure (device Secure Enclave, server-side
   HSM, or equivalent). Compromise of this key allows unauthorized L2 creation.
   See [security-model.md §3.5](security-model.md#35-deployment-models).

3. **Agent key scope**: The agent's private key grants authority ONLY within the
   constraints specified in L2 mandates. The agent cannot expand its own
   authority.

4. **Merchant checkout JWT authenticity**: The merchant's checkout JWT is assumed to
   accurately represent the checkout contents. The merchant signs the checkout, and the
   `checkout_hash` / `transaction_id` mechanism binds it to the payment mandate.

5. **Clock synchronization**: Parties are assumed to have loosely synchronized
   clocks. See §10.4 for specific tolerance values.

### 5.3 Verification Requirements Per Role

**Merchant MUST:**
- Verify L1 signature against the Credential Provider's published JWKS
- Verify L2 signature against the key in L1 `cnf.jwk`
- Verify `sd_hash` bindings between layers
- Verify checkout mandate disclosure matches the submitted checkout
- In Autonomous mode: resolve agent key from L2 `cnf.jwk` via L3b header `kid` match against L2 `cnf.kid`, then verify L3b signature
- In Autonomous mode: verify L3b `typ` header is `kb-sd-jwt`

> Note: In deployments where the merchant delegates credential verification to
> a payment processor or gateway, these requirements apply to the entity
> performing verification on the merchant's behalf.

**Payment Network MUST:**
- Verify L1 signature against the Credential Provider's published JWKS
- Verify L2 signature against the key in L1 `cnf.jwk`
- Verify `sd_hash` bindings between layers
- Ensure a payment mandate disclosure is present and well-formed
- In Autonomous mode: verify L2 `typ` header is `kb-sd-jwt+kb`
- In Autonomous mode: verify L3a payment values satisfy disclosed L2 payment constraints
- In Autonomous mode: resolve agent key from L2 `cnf.jwk` via L3a header `kid` match against L2 `cnf.kid`, then verify L3a signature
- In Autonomous mode: verify L3a `typ` header is `kb-sd-jwt`
- In Autonomous mode: enforce one-L3-per-mandate-pair and track cumulative L3 spend per L2 (see [security-model.md §4.2](security-model.md#42-cross-merchant-replay))
- In Autonomous mode: verify cross-reference (`transaction_id` in L3a == `checkout_hash` in L3b) when both are available
- Verify `checkout_hash` / `transaction_id` binding between checkout and payment mandates (when both are disclosed)
- In Autonomous mode: verify `payment.reference` constraint — `conditional_transaction_id` matches the checkout mandate's `checkout_hash`
- Verify credential expiration at all layers

**Agent Platform SHOULD:**
- Verify L1 and L2 integrity before using credentials
- Verify constraint satisfaction before presenting L3 to merchant

---

## 6. Technology Foundations

VI is built on the following established standards and technologies:

| Technology | Specification | Role in VI |
|------------|--------------|------------|
| **SD-JWT** | [RFC 9901] | Base credential format; provides selective disclosure of claims via salted hash commitments |
| **JWS** | [RFC 7515] | Digital signature structure for all JWT layers |
| **JWK** | [RFC 7517] | Public key representation in `cnf` claims and JWT headers |
| **JWA** | [RFC 7518] | Algorithm identifiers (`ES256`) |
| **JWT** | [RFC 7519] | Claim structure and processing rules |
| **Confirmation Methods** | [RFC 7800] | `cnf` claim for key binding at each delegation layer |
| **ES256** | [RFC 7518] §3.4 | ECDSA using P-256 and SHA-256; REQUIRED signing algorithm |
| **SHA-256** | [FIPS 180-4] | Hash algorithm for disclosures, `sd_hash`, and `checkout_hash` |
| **Base64url** | [RFC 4648] §5 | Encoding for signatures, disclosures, and hash values (no padding) |

### Algorithm Requirements

Implementations MUST support ES256 (ECDSA using the P-256 curve and SHA-256)
as defined in [RFC 7518] Section 3.4. The `_sd_alg` claim MUST be `"sha-256"`.

Future versions of this specification MAY define additional algorithms
(e.g., EdDSA with Ed25519).

See [design-rationale.md §5](design-rationale.md#5-signing-algorithm-es256) for the rationale behind requiring a single algorithm.

---

## 7. Credential Lifecycle

The VI credential lifecycle follows a layered issuance, mandate creation, and
verification flow:

```
                  ┌──────────────────────┐
                  │  1. ENROLLMENT       │
                  │  User registers      │
                  │  public key with     │
                  │  Credential Provider │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │  2. L1 ISSUANCE      │
                  │  Credential Provider │
                  │  signs SD-JWT with   │
                  │  user identity +     │
                  │  cnf.jwk binding     │
                  │  typ: "sd+jwt"       │
                  └──────────┬───────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
     ┌───────────────────┐    ┌───────────────────┐
     │ 3a. L2 IMMEDIATE  │    │ 3b. L2 AUTONOMOUS │
     │ User confirms     │    │ User sets          │
     │ final checkout +   │    │ constraints +      │
     │ payment values    │    │ binds agent key    │
     │ typ: "kb-sd-jwt"  │    │ typ: "kb-sd-jwt+kb"│
     └────────┬──────────┘    └────────┬──────────┘
              │                        │
              │                        ▼
              │               ┌───────────────────┐
              │               │ 4. L3 CREATION    │
              │               │ Agent selects      │
              │               │ products, creates  │
              │               │ checkout, fills    │
              │               │ values within      │
              │               │ constraints        │
              │               │ typ: "kb-sd-jwt"   │
              │               └────────┬──────────┘
              │                        │
              ├────────────────────────┘
              ▼
     ┌───────────────────┐
     │ 5. PRESENTATION   │
     │ Selective          │
     │ disclosure to      │
     │ merchant (checkout)│
     │ and network        │
     │ (payment)          │
     └────────┬──────────┘
              │
              ▼
     ┌───────────────────┐
     │ 6. VERIFICATION   │
     │ Chain signature    │
     │ validation,        │
     │ sd_hash binding,   │
     │ constraint check,  │
     │ checkout_hash bind  │
     └────────┬──────────┘
              │
              ▼
     ┌───────────────────┐
     │ 7. SETTLEMENT     │
     │ Payment network    │
     │ authorizes with    │
     │ assurance data     │
     └───────────────────┘
```

**Step-by-step flow (Autonomous mode):**

1. **Enrollment**: User registers a public key with the Credential
   Provider, associating it with their account.

2. **L1 Issuance**: The Credential Provider creates an SD-JWT (`typ: "sd+jwt"`) containing the
   user's identity claims (selectively disclosable) and binds the user's
   public key via `cnf.jwk`. This credential is long-lived (~1 year). Does NOT contain `sd_hash` (root credential).

3. **L2 Creation**: When the user wants to delegate a purchase to an agent,
   the user creates a KB-SD-JWT+KB (`typ: "kb-sd-jwt+kb"`) containing:
   - Checkout constraints (line items, quantities, allowed merchants)
   - Payment constraints (amount range, approved payees, `payment_instrument`)
   - The agent's public key bound via `cnf` (`kid` + `jwk`) in each mandate
   - An `sd_hash` binding this layer to the serialized L1

4. **L3 Creation**: The agent browses the merchant's catalog, selects products
   that satisfy the checkout constraints, and obtains a merchant-signed checkout JWT.
   The agent then builds two KB-SD-JWTs (`typ: "kb-sd-jwt"`): L3a (payment mandate for the network) and
   L3b (checkout mandate for the merchant). Each L3 includes a selective `sd_hash`
   binding to the relevant L2 disclosures and the agent's `kid` in the JWT header.
   L3a carries `transaction_id` and L3b carries `checkout_hash`, which MUST be equal,
   cross-referencing the two credentials. Neither L3 contains a `cnf` claim (terminal delegation).

5. **Presentation**: The agent presents L3b (with checkout mandate disclosure)
   to the merchant for order verification, and L3a (with payment mandate disclosure)
   to the payment network for authorization. Each party sees only the mandate
   relevant to its role.

6. **Verification**: The merchant verifies L3b against the checkout disclosure; the
   payment network verifies L3a against the payment disclosure, checks that L3a
   values satisfy disclosed L2 constraints, validates the `typ` headers at each layer,
   and validates the `checkout_hash` / `transaction_id` cross-reference binding.

7. **Settlement**: The payment network returns assurance data confirming chain
   validity, constraint satisfaction, and authorization status.

**Step-by-step flow (Immediate mode):**

In Immediate mode, the user is present and confirms final transaction values
directly. There is no Layer 3 — the agent assists with checkout but creates no
credentials. The agent creates the `checkout_jwt` representing the cart
contents; the user reviews and confirms the transaction; and the merchant
validates the checkout mandate contents against its own records when L2 is
presented. The user's L2 signature over finalized values is the core
authorization mechanism.

1. **Enrollment and L1 Issuance**: Same as Autonomous mode (steps 1–2 above).

2. **Agent builds checkout**: The agent (or user) browses the merchant's
   catalog, selects products, and initiates checkout. During this interaction
   the merchant has the opportunity to record the checkout session details
   (items, quantities, prices). The agent creates a `checkout_jwt` — a JWT
   representing the cart contents: item identifiers, quantities, unit prices,
   currency, and merchant identifier. (Per [credential-format.md §6.3](credential-format.md#63-checkout_jwt--checkout-object-representation), the `checkout_jwt` SHOULD be
   signed by the merchant, but this is implementation-defined in v0.1.)

3. **User reviews and creates L2**: The user reviews the cart contents and
   payment details presented by the agent. If the user confirms, the user (or
   user's device) creates a KB-SD-JWT (`typ: "kb-sd-jwt"`) containing:
   - A checkout mandate with the `checkout_jwt` and its
     `checkout_hash` (`B64U(SHA-256(ASCII(checkout_jwt)))`)
   - A payment mandate with finalized payment values (`amount`, `currency`,
     `payee`, `payment_instrument`) and `transaction_id` set to the same
     `checkout_hash` value
   - An `sd_hash` binding this layer to the serialized L1
   - No `cnf` in either mandate — the user signs final values directly, with
     no agent delegation

4. **Agent forwards credentials**: The agent forwards L1 + L2 to the merchant
   and payment network. The agent creates no Layer 3 — it acts as a transport
   mechanism only. The credential chain terminates at L2.

5. **Merchant verification**: The merchant receives L2 with the checkout
   mandate disclosed. The merchant:
   - Verifies the L1 → L2 signature chain (L1 signature against Credential
     Provider JWKS; L2 signature against the key in L1 `cnf.jwk`)
   - Verifies `sd_hash` binding between L2 and L1
   - Extracts the `checkout_jwt` from the disclosed checkout mandate
   - Validates the checkout contents (items, quantities, prices) against its
     own catalog and records — the merchant confirms the cart represents a
     valid order it is willing to fulfill. If the `checkout_jwt` is
     merchant-signed, the merchant can also verify its own signature for
     additional integrity assurance.
   - Recomputes `B64U(SHA-256(ASCII(checkout_jwt)))` and verifies it matches
     the `checkout_hash` on the checkout mandate

   At this point the merchant has assurance that: (a) the checkout contents
   are consistent with its own catalog and checkout records, and (b) the
   user's L2 signature proves the user authorized this specific checkout.
   No L3 is needed — if the merchant agrees with what it sees in L2, it can
   proceed directly.

6. **Payment network verification**: The payment network receives L2 with the
   payment mandate disclosed. The network:
   - Verifies the L1 → L2 signature chain
   - Verifies `sd_hash` binding
   - Extracts the payment mandate with finalized values (`amount`, `currency`,
     `payee`, `transaction_id`)
   - Verifies the `transaction_id` matches `checkout_hash` (when both mandates
     are available), binding the payment authorization to the specific checkout
   - Authorizes the payment

7. **Settlement**: The payment network returns assurance data confirming chain
   validity and authorization status. No constraint checking is needed — values
   are final, not constrained.

**Immediate mode example walkthrough:**

Scenario: A user purchases a Babolat Pure Aero racket ($279.99) from Tennis
Warehouse, assisted by an agent, using their Mastercard (ending 8842).

- **L1**: Credential Provider (Mastercard) issues SD-JWT binding user's key.
  Same as Autonomous example.

- **Agent builds checkout**: The agent browses Tennis Warehouse on the user's
  behalf and adds the Babolat Pure Aero to the cart. Tennis Warehouse records
  the checkout session. The agent creates a `checkout_jwt`:
  ```
  checkout_jwt payload: {
    "merchant": {"id": "tw-001", "name": "Tennis Warehouse"},
    "items": [{"sku": "BAB86345", "name": "Babolat Pure Aero",
               "quantity": 1, "unit_price": 27999}],
    "currency": "USD",
    "total": 27999
  }
  ```

- **L2**: The user reviews the cart, confirms, and signs L2 (`typ: kb-sd-jwt`):
  - Checkout mandate: `vct=mandate.checkout`,
    `checkout_jwt={agent-created JWT}`,
    `checkout_hash={SHA-256 of checkout_jwt}`
  - Payment mandate: `vct=mandate.payment`,
    `payment_instrument={card, ...}`, `currency=USD`, `amount=27999`,
    `payee={Tennis Warehouse}`, `transaction_id={same hash}`
  - No `cnf` in mandates — no delegation

- **Presentation**: Agent forwards L1 + L2. Checkout mandate disclosed to
  Tennis Warehouse; payment mandate disclosed to payment network.

- **Verification**:
  1. Tennis Warehouse verifies L1 signature → valid (Mastercard's key)
  2. Tennis Warehouse verifies L2 signature → valid (user's key from L1 `cnf.jwk`)
  3. Tennis Warehouse verifies `sd_hash` → L2 bound to L1 ✓
  4. Tennis Warehouse extracts `checkout_jwt` from checkout mandate
  5. Tennis Warehouse validates checkout contents against its catalog and
     checkout session records → items, quantities, prices match ✓
  6. Tennis Warehouse recomputes hash → matches `checkout_hash` ✓
  7. Payment network verifies chain, authorizes $279.99 to Tennis Warehouse
  8. `transaction_id` on payment mandate matches `checkout_hash` →
     payment bound to checkout ✓

> **Comparison with Autonomous mode:** In Autonomous mode, the agent creates
> L3 to prove it fulfilled the user's constraints — the merchant validates the
> `checkout_jwt` in L3b, and the payment network validates constraint
> satisfaction. In Immediate mode, there are no constraints to check and no L3
> to create. The merchant validates the checkout directly from L2 against its
> own records. In both modes, the merchant's acceptance of the checkout contents
> is what ultimately confirms the cart is valid.

---

## 8. Checkout-Payment Integrity

### 8.1 The Binding Problem

In a transaction, the checkout mandate (what is being bought) and the payment
mandate (how it is being paid for) are disclosed to different parties. The
merchant sees the checkout; the payment network sees the payment. Without a binding
mechanism, there is no guarantee that the payment amount corresponds to the
actual checkout contents.

### 8.2 `checkout_hash` / `transaction_id` Binding

VI uses a SHA-256 hash of the `checkout_jwt` string to bind checkout and payment
mandates:

```
hash = B64U(SHA-256(ASCII(checkout_jwt)))
```

Where:
- `checkout_jwt` is the merchant-signed JWT string representing the checkout contents

The checkout mandate carries this hash as `checkout_hash`; the payment mandate
carries the same hash as `transaction_id`. The verifier recomputes the hash from
the disclosed `checkout_jwt` and compares it to both values.

### 8.3 Cross-Reference Binding (Autonomous Mode)

In Autonomous mode, the split L3 architecture produces two credentials:
- L3a (payment) contains `transaction_id`
- L3b (checkout) contains `checkout_hash`

These values MUST be equal: `L3a.transaction_id == L3b.checkout_hash`. This
cross-reference ensures that the payment authorization and checkout fulfillment
refer to the same transaction, even though they are presented to different parties.

At the L2 level, the `payment.reference` constraint carries a
`conditional_transaction_id` that binds the payment mandate to the checkout
mandate at delegation time, before the checkout JWT exists.

### 8.4 Verification

When both checkout and payment mandates are disclosed to a verifier, the verifier
MUST:

1. Recompute the hash from the disclosed `checkout_jwt`.
2. Compare the computed hash to `checkout_hash` on the checkout mandate and
   `transaction_id` on the payment mandate. In Autonomous mode, verify
   `transaction_id == checkout_hash` across L3a and L3b.
3. Reject the transaction if any binding check fails.

> **Note:** In the split L3 architecture, the merchant receives L3b and the payment network receives L3a. Each party verifies its own L3 independently. The cross-reference check (`transaction_id == checkout_hash`) is performed when a verifier has access to both L3 credentials (e.g., during dispute resolution). Structural verification (signatures, sd_hash, key delegation) applies to each L3 independently.

---

## 9. Extensibility

### 9.1 Constraint Type Registry

VI defines a set of registered constraint types (see
[constraints.md](constraints.md)) using a dot-notation namespace:

| Namespace | Purpose | Examples |
|-----------|---------|---------|
| `mandate.checkout.*` | Checkout-related constraints | `mandate.checkout.line_items`, `mandate.checkout.allowed_merchant` |
| `payment.*` | Payment-related constraints | `payment.amount`, `payment.allowed_payee` |

Implementations MUST support all registered constraint types.

**Extension mechanisms:**

- **URI-namespaced types**: Organizations MAY define custom constraint types
  using URI naming (e.g., `urn:example:loyalty-points`). Verifiers that do not
  recognize a URI-namespaced type SHOULD skip it in permissive mode.

- **Private types**: For internal or experimental use, implementations MAY use
  the `x-` prefix (e.g., `x-internal-priority`). Private types MUST NOT appear
  in production credentials exchanged across organizational boundaries.

### 9.2 Agent Attestation

VI supports an optional `agent_attestation` claim for carrying agent identity
or security attestations:

```json
{
  "agent_attestation": {
    "type": "<attestation-scheme>",
    "value": "<attestation-payload>"
  }
}
```

The `type` field identifies the attestation scheme. Implementations that do not
recognize the attestation type MUST ignore the claim (not reject the
credential). Future companion documents will define specific attestation
schemes.

### 9.3 Protocol Integration

VI is designed as a standalone standard that other protocols can integrate.
Protocol-specific mappings (e.g., how VI credentials map to a particular payment
protocol's authorization flow) are documented in dedicated integration guides,
not in the core specification.

See the `protocol-landscape/` directory for protocol-specific mapping documents.

---

## 10. Conformance

### 10.1 Issuer (L1) Conformance

A conformant Issuer implementation:

1. MUST issue Layer 1 SD-JWTs with the `alg`, `typ`, and `kid` header
   parameters as specified in [credential-format.md §3](credential-format.md#3-layer-1-credential-provider-sd-jwt).
2. MUST set `typ` header to `sd+jwt` in L1.
3. MUST include the `cnf.jwk` claim containing the user's public key.
4. MUST include a `vct` claim containing a well-formed URI identifying the payment credential type as an always-visible claim in the JWT payload (not selectively disclosable). Implementations using the Mastercard reference profile MUST use `"https://credentials.mastercard.com/card"`.
5. MUST include all always-visible claims required by the credential's VCT profile. For the Mastercard reference profile, this means `pan_last_four` and `scheme` as REQUIRED always-visible claims, and `card_id` as an OPTIONAL always-visible claim.
6. MUST support selective disclosure for user identity claims.
7. MUST publish a JWKS endpoint for key discovery by verifiers.
8. SHOULD set L1 expiration to no more than 1 year.

### 10.2 L2 Construction Conformance

A conformant L2 construction implementation:

1. MUST create Layer 2 KB-SD-JWTs or KB-SD-JWT+KBs signed by the key bound in L1 `cnf.jwk`.
2. MUST compute `sd_hash` as specified in
   [credential-format.md §6](credential-format.md#6-hash-binding-mechanisms).
3. MUST set `typ` header to `kb-sd-jwt` for Immediate mode or `kb-sd-jwt+kb`
   for Autonomous mode.
4. In Immediate mode: mandates MUST contain final values and MUST NOT contain
   `cnf` claims.
5. In Autonomous mode: mandates MUST contain `cnf.jwk` binding the agent's
   public key and `cnf.kid` with the key identifier, and MUST contain at least one constraint.
6. In Immediate mode: MUST compute the SHA-256 hash of `checkout_jwt` and
   include it as `checkout_hash` in the checkout mandate and as `transaction_id`
   in the payment mandate when both mandates are present.
   In Autonomous mode: MUST include a `payment.reference` constraint with
   `conditional_transaction_id` in the payment mandate.

> **Deployment note:** The user's private key may reside on-device (Secure
> Enclave), server-side (custodial HSM), or in a hybrid arrangement. The
> conformance requirements above apply regardless of deployment model. See
> [security-model.md §3.5](security-model.md#35-deployment-models) for
> security considerations across deployment models.

### 10.3 Agent Conformance

A conformant Agent implementation (Autonomous mode):

1. MUST create two Layer 3 KB-SD-JWTs (L3a payment, L3b checkout) signed by
   the key bound in L2 mandate `cnf.jwk`.
2. MUST set `typ` header to `kb-sd-jwt` in both L3a and L3b.
3. MUST include a `kid` parameter in each L3 JWT header matching L2 `cnf.kid`. MUST NOT include a `jwk` parameter in L3 headers.
4. MUST NOT include a `cnf` claim in L3 payloads (terminal delegation).
5. MUST compute selective `sd_hash` for each L3, binding it to the L2 base JWT
   plus the relevant L2 disclosures (payment + merchant for L3a, checkout + item
   for L3b).
6. MUST produce final values that satisfy all L2 constraints.
7. SHOULD set L3 expiration to no more than 1 hour. RECOMMENDED: 5 minutes.
8. MUST ensure `transaction_id` in L3a equals `checkout_hash` in L3b, both
   computed as `B64U(SHA-256(ASCII(checkout_jwt)))`.

### 10.4 Verifier Conformance

A conformant Verifier implementation:

1. MUST verify ES256 signatures at every layer of the presented chain.
2. In production deployments, MUST provide the Credential Provider public key (or JWKS-resolved key) to perform L1 signature verification. Skipping L1 signature verification is acceptable only in controlled test environments.
3. MUST verify the `typ` header at each layer:
   - L1: `sd+jwt`
   - L2 Immediate: `kb-sd-jwt`
   - L2 Autonomous: `kb-sd-jwt+kb`
   - L3a and L3b: `kb-sd-jwt`
4. MUST verify the delegation chain (L1 `cnf` → L2 signer; L2 mandate `cnf` →
   L3 signer).
5. MUST verify `sd_hash` bindings between adjacent layers.
6. MUST check credential expiration at all layers (RECOMMENDED clock skew
   tolerance: 300 seconds).
7. In Autonomous mode: MUST resolve the agent's public key from L2 mandate
   `cnf.jwk` by matching L3 header `kid` against L2 `cnf.kid`. MUST NOT trust a self-asserted `jwk` in L3 headers.
8. In Autonomous mode: MUST verify L3 payloads do NOT contain `cnf` claims.
9. When both checkout and payment mandates are disclosed: MUST verify `checkout_hash`
   (on checkout mandate) matches `transaction_id` (on payment mandate).
   In Autonomous mode, verify `transaction_id == checkout_hash` cross-reference.
10. MUST check L3 values against **disclosed** L2 constraints. Machine-enforceable constraints (amount range, allowed payee, merchant, line items) MUST be verified; descriptive fields (product description, brand, color, size) are informational and not subject to automated verification.
11. When receiving partial L2 disclosures: MUST still verify the structural
   chain (signatures, `sd_hash`, key delegation). Content checks (checkout-payment
   binding, constraint checking) apply only to disclosed mandates. At least one
   mandate disclosure is REQUIRED in Autonomous mode to extract the agent
   delegation key.

---

## 11. Security Considerations

This section provides a brief overview of security considerations. For a
comprehensive threat model and security analysis, see
[security-model.md](security-model.md).

| Threat | Mitigation |
|--------|------------|
| **Agent exceeds authority** | L2 constraints are cryptographically bound; L3 values are checked against **disclosed** L2 constraints at verification time |
| **Credential replay** | `nonce` and `aud` claims prevent cross-context replay; short L3 lifetime (~5 min) limits replay window |
| **Cross-merchant replay** | Each mandate pair is expected to produce exactly one L3a + L3b pair; payment networks MUST enforce by tracking L3 issuance per mandate pair and cumulative spend per L2 (see [security-model.md §4.2](security-model.md#42-cross-merchant-replay)) |
| **Checkout-payment mismatch** | `checkout_hash` binding and `transaction_id` cross-reference ensure payment corresponds to specific checkout |
| **Key compromise (Credential Provider)** | Key rotation via JWKS; short-lived L2/L3 limit blast radius; payment network retains independent transaction-level controls (card cancellation, fraud screening); VI-layer credential revocation deferred to future version (see [security-model.md §6.1](security-model.md#61-revocation)) |
| **Key compromise (User)** | Secure Enclave/HSM protection (see [security-model.md §3.5](security-model.md#35-deployment-models)); L1 expiration limits exposure |
| **Key compromise (Agent)** | L2 constraints limit damage; short L3 lifetime; agent key is bound to specific L2 — cannot be reused with different constraints |
| **Disclosure correlation** | Random salts on each disclosure; different salts per issuance prevent cross-transaction correlation |
| **L2 mandate tampering** | ES256 signature by the key bound in L1 `cnf.jwk`; any modification invalidates the signature |
| **sd_hash manipulation** | sd_hash covers the L2 base JWT and relevant disclosures per L3 type; modification or inconsistency in the presented disclosure set is detected |
| **Type confusion attacks** | Explicit `typ` header checking at each layer prevents attackers from presenting L3 as L2 or mismatching credential types |

---

## 12. References

### Normative References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.

- **[RFC 4648]** Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.

- **[RFC 7515]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature
  (JWS)", RFC 7515, May 2015.

- **[RFC 7517]** Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.

- **[RFC 7518]** Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, May 2015.

- **[RFC 7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token
  (JWT)", RFC 7519, May 2015.

- **[RFC 7800]** Jones, M., Bradley, J., and H. Tschofenig, "Proof-of-
  Possession Key Semantics for JSON Web Tokens (JWTs)", RFC 7800, April 2016.

- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.

- **[RFC 8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
  Interchange Format", STD 90, RFC 8259, December 2017.

- **[FIPS 180-4]** National Institute of Standards and Technology, "Secure
  Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

- **[RFC 9901]** Fett, D., Yasuda, K., and B. Campbell, "Selective Disclosure
  for JSON Web Tokens (SD-JWT)", RFC 9901, November 2025.

### Informative References

- **[FIDO2]** FIDO Alliance, "FIDO2: Web Authentication (WebAuthn)", 2019.

- **[W3C-VC]** Sporny, M., Noble, G., Longley, D., Burnett, D., and
  B. Zundel, "Verifiable Credentials Data Model v2.0", W3C Recommendation.
