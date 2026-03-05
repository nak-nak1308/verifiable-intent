# Verifiable Intent: Design Rationale

This document explains the key design decisions in the Verifiable Intent (VI)
specification. It is informative, not normative.

---

## 1. Why SD-JWT?

VI requires a credential format that supports selective disclosure (each party
in a transaction sees only the claims they need) while remaining compact enough
for payment flows. Four candidate formats were evaluated:

| Format | Selective Disclosure | Compactness | Standards Status | Ecosystem Fit |
|--------|---------------------|-------------|------------------|---------------|
| **SD-JWT** | Native (salted hash commitments) | Compact (base64url) | IETF RFC 9901 | JSON-native, JWT ecosystem |
| W3C VC + JWT | Requires VC-specific profiles | Moderate | W3C Recommendation | Broad but no native SD |
| W3C VC + JSON-LD | Via BBS+ signatures (complex) | Verbose | W3C Recommendation | Academic/government focus |
| AnonCreds / ZKP | Native (zero-knowledge proofs) | Variable | Hyperledger | Limited payments adoption |
| mDL (ISO 18013-5) | Per data element (within `nameSpaces`) | CBOR (binary) | ISO standard | Mobile identity, not payments |

**Decision: SD-JWT** (IETF RFC 9901, formerly draft-ietf-oauth-selective-disclosure-jwt).

**Rationale:**

1. **Native selective disclosure.** Each claim is individually disclosable via
   salted hash commitments. No additional cryptographic machinery (BBS+, ZKP
   circuits) required. This matches VI's core need: the merchant sees the checkout
   mandate but not the payment details; the network sees the payment mandate
   but not the checkout.

2. **IETF standardization track.** SD-JWT is on the IETF OAuth working group
   standards track, giving it institutional legitimacy for payments
   infrastructure. W3C VCs are a recommendation but lack a single canonical
   selective disclosure mechanism.

3. **Compact format.** Base64url-encoded JSON with `~`-delimited disclosures
   fits in HTTP headers, query parameters, and payment protocol message fields
   where binary formats (CBOR) or verbose formats (JSON-LD) would not.

4. **JSON ecosystem alignment.** Payment APIs (Google AP2, Mastercard ACP,
   EMVCo SRC) are JSON-based. SD-JWT integrates without format translation.

---

## 2. Relationship to OpenID4VP

OpenID for Verifiable Presentations (OpenID4VP) defines a protocol for
requesting and presenting verifiable credentials. VI credentials can be
transported via OpenID4VP, but VI itself is a credential format specification,
not a presentation protocol.

**Key distinction:** OpenID4VP answers "how do I request and deliver a
credential?" VI answers "what is inside the credential and how do I verify the
delegation chain?"

A future integration guide may define VI credential presentation via OpenID4VP
`vp_token` parameters. The SD-JWT format choice makes this integration
straightforward since OpenID4VP already supports SD-JWT as a credential format.

---

## 3. Relationship to FIDO2/WebAuthn

FIDO2 and WebAuthn provide strong user authentication using public key
cryptography, typically with the P-256 curve that VI also uses for ES256
signatures. However, **VI credentials are not WebAuthn credentials**, and the
relationship is one of complementary deployment patterns rather than direct
technical integration.

**Key distinctions:**

- **FIDO2/WebAuthn** authenticates the user to a relying party ("this person is
  who they claim to be") using origin-scoped credentials.
- **VI** authorizes a specific transaction ("this person approved this purchase
  with these constraints") using payment-scoped credentials.

**Deployment complementarity:**

In a production deployment, the user's VI signing key (bound in L1 `cnf.jwk`)
may be stored in the same secure hardware (device Secure Enclave, HSM) that
stores WebAuthn credentials. User authorization flows might combine both:

1. **WebAuthn assertion** authenticates the user to the wallet application
2. **VI L2 signing** authorizes the specific transaction with the user's key

These are **separate cryptographic operations** using **separate keys**:
- WebAuthn key: Origin-scoped, used for authentication assertions
- VI key: Payment network-scoped, used for signing VI credentials

The VI signing operation would typically be gated by biometric authentication
(Face ID, Touch ID, Windows Hello) using the same local authentication
mechanisms that WebAuthn uses, but the VI credential itself is not a WebAuthn
credential.

**Hardware alignment:**

The choice of ES256 (ECDSA over P-256) as VI's signing algorithm benefits from
the same hardware ecosystem that supports WebAuthn:
- Mobile device Secure Enclaves (Apple, Android) support P-256
- Hardware security modules (HSMs) support P-256
- Cloud KMS services support P-256

This hardware availability was a factor in the ES256 choice, though the primary
motivation was broader HSM compatibility for payment infrastructure deployments
(see §5).

---

## 4. Relationship to SCA/PSD2

Strong Customer Authentication (SCA) under PSD2 requires that electronic
payments include authentication elements linked to a specific amount and payee
(dynamic linking). VI's constraint model provides a cryptographic
implementation of dynamic linking:

- **Amount binding:** The `payment.amount` constraint cryptographically limits
  the transaction amount to a min/max range. The L3a `amount` must satisfy this
  constraint for verification to succeed.
- **Payee binding:** The `payment.allowed_payee` constraint specifies allowed merchants.
  Only transactions to listed payees pass verification.
- **Checkout-payment binding:** The `checkout_hash` and `conditional_transaction_id` mechanisms
  bind the payment authorization to a specific set of goods, going beyond
  PSD2's amount-and-payee requirement.

VI does not replace SCA — it provides the cryptographic evidence that a
compliant SCA implementation can produce and verify.

---

## 5. Signing Algorithm: ES256

**Decision:** ES256 (ECDSA over NIST P-256) as the required signing algorithm.

**Rationale:**

1. **HSM and Secure Enclave compatibility.** P-256 is supported by all major
   hardware security modules (AWS CloudHSM, Azure Dedicated HSM, Google Cloud
   HSM) and mobile secure enclaves (Apple Secure Enclave, Android Keystore).
   This is essential for production key management.

2. **Compact signatures.** ES256 produces 64-byte signatures (two 32-byte
   integers), keeping SD-JWT tokens compact.

3. **FIDO2/WebAuthn alignment.** P-256 is the mandatory-to-implement curve in
   WebAuthn, enabling the same secure hardware to store both authentication
   credentials (WebAuthn) and authorization credentials (VI), though they
   remain separate keys with separate purposes.

4. **Payment ecosystem precedent.** Google's Agent Payments Protocol (AP2)
   examples use ES256. EMVCo tokenization specifications reference P-256 for
   device binding.

**Future:** EdDSA (Ed25519) is planned as an optional algorithm in a future
version. Ed25519 offers deterministic signatures and simpler implementation,
but has less HSM support today.

---

## 6. Delegation Model: Layered `cnf` Claims

VI uses the `cnf` (confirmation) claim from RFC 7800 to build a delegation
chain across SD-JWT layers. This is the specification's core novel
contribution.

**How it works:**

- **Layer 1** (Issuer SD-JWT): `cnf.jwk` binds the user's public key.
  The issuer asserts "this key belongs to this user."
- **Layer 2** (User KB-SD-JWT): In Autonomous mode, each mandate includes
  `cnf.kid` and `cnf.jwk` binding the agent's public key. The user asserts
  "this agent key may act within these constraints."
- **Layer 3** (Agent KB-SD-JWT): The `kid` in the header identifies the
  delegated agent key, which verifiers resolve from L2 `cnf.jwk`. The agent
  asserts "I am the authorized agent, and here are the final transaction
  details." L3 contains no `cnf` claim — the delegation chain terminates
  here, preventing further sub-delegation.

**Why `cnf` claims instead of custom fields:**

1. **Standard mechanism.** RFC 7800 is the established JWT method for proof of
   possession. Reusing it avoids inventing new verification semantics.
2. **Presence/absence encodes mode.** In Immediate mode, L2 mandates have no
   `cnf` — the user signs final values directly. In Autonomous mode, L2
   mandates include `cnf.jwk` — the user delegates to an agent. The
   presence or absence of `cnf` in mandates is the technical distinction
   between "user-final" and "agent-delegated."
3. **Verifier simplicity.** Verifiers follow the same `cnf` → key extraction →
   signature verification pattern at each layer, regardless of mode.

> **Relationship to RFC 7800:** In standard RFC 7800 usage, `cnf.jwk` names the
> key that proves possession of the *current* JWT. VI applies a profile-specific
> extension of this semantics for multi-party delegation: `cnf.jwk` in a mandate
> names the key authorized to create the *next* layer. While the verification
> mechanics (extract key from `cnf`, verify signature) follow the same pattern,
> VI's use is a profile-level application that broadens the semantic scope from
> "holder of this token" to "authorized delegate for this mandate."

---

## 7. Two Execution Modes

**Decision:** VI defines two modes (Immediate and Autonomous) rather than a
single general-purpose flow.

**Rationale:**

- **Immediate mode** (2-layer) covers the common case where the user is present
  and confirms final values directly. No agent delegation, no constraints, no
  L3. This is the simpler flow and should be the default for most transactions.
- **Autonomous mode** (3-layer) covers the case where an AI agent acts on the
  user's behalf without real-time confirmation. The additional layer (L3) and
  constraint system add complexity but provide the cryptographic authorization evidence
  needed when the end-user is not in the loop.

Collapsing these into a single mode would either over-complicate simple
transactions (requiring empty constraint sets and unnecessary L3 for end-user-
present flows) or under-protect autonomous transactions (allowing unconstrained
agent actions).

---

## 8. Why Constraints Instead of Top-Level Recurrence?

Earlier VI drafts included `recurrence` as a top-level field on payment
mandates, treating subscription setup as distinct from constraint-based
delegation. V0.1 replaces this with two constraint types: `payment.recurrence`
(merchant-managed subscriptions) and `payment.agent_recurrence` (agent-managed
recurring purchases).

**Rationale:**

1. **Unified enforcement model.** All agent authority bounds — whether
   per-transaction limits, merchant allowlists, or recurring purchase terms —
   are constraints. This gives verifiers a single validation framework rather
   than separate logic for "recurrence fields vs. constraints."

2. **Clearer mode distinction.** The presence of constraints signals
   Autonomous mode delegation. Top-level recurrence fields obscured this — a
   mandate with only `recurrence` but no other constraints looked like
   Immediate mode data, not a delegated authority grant.

3. **Multi-transaction support.** `payment.agent_recurrence` explicitly
   authorizes the agent to create multiple L3 pairs over time (the
   multi-transaction mandate pair model), paired with `payment.budget` to cap
   cumulative spend. This is a natural extension of the constraint model;
   top-level fields provided no clear path for this.

4. **Subscription setup clarity.** `payment.recurrence` makes it explicit that
   the transaction is a subscription setup (one L3, merchant charges
   thereafter). The constraint validates setup parameters against user intent.

---

## 9. Why One-L3-Per-Pair in v0.1 Base Model?

V0.1 defines one-L3-per-mandate-pair as the base transaction model, with
`payment.agent_recurrence` as an explicit extension that authorizes multiple L3
fulfillments.

**Rationale:**

1. **Simpler security model.** A one-to-one mapping between mandate pairs and
   transactions (in the base case) eliminates replay and over-spend attack
   classes. Payment networks enforce this through stateful tracking (see
   [security-model.md §4.2](security-model.md#42-cross-merchant-replay)), and
   the invariant is straightforward to audit.

2. **Establishes enforcement infrastructure.** The stateful tracking that
   payment networks build for one-L3-per-pair (transaction logs keyed by L2
   `sd_hash` and mandate pair index) is the same infrastructure that
   multi-transaction mandate pairs build on. Starting with the simpler
   invariant lets implementations validate their tracking before adding
   bounded multiplicity.

3. **Subscription setup covers immediate need.** The `payment.recurrence`
   constraint lets an agent establish a subscription with a single L3 pair.
   Subsequent recurring charges are merchant-initiated on normal payment rails
   (card-on-file, network tokens). This covers the most common recurring
   payment pattern.

4. **Explicit multi-transaction opt-in.** The `payment.agent_recurrence`
   constraint explicitly signals "this mandate pair authorizes multiple L3
   fulfillments" with clear bounds (`max_occurrences`, `payment.budget`
   cumulative cap, date range). This makes the multi-transaction authorization
   an intentional, verifiable choice rather than an implicit behavior.

**Transaction scope models in v0.1:**

- **Single-transaction** (base): One L3 pair per mandate pair
- **Subscription setup**: `payment.recurrence` constraint; one L3 pair starts
  merchant-managed recurring charges
- **Multi-transaction**: `payment.agent_recurrence` constraint; multiple L3
  pairs within bounds (occurrence cap, budget cap, date range)

---

## References

- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) — Selective Disclosure for JSON Web Tokens (SD-JWT)
- [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) — Proof-of-Possession Key Semantics for JWTs
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) — OpenID for Verifiable Presentations
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) — Web Authentication API
- [PSD2 RTS on SCA](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32018R0389) — EU delegated regulation on Strong Customer Authentication
