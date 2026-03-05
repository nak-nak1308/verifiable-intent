# Verifiable Intent — Constraint Type Definitions and Validation Rules

**Version**: 0.1-draft
**Status**: Draft
**Date**: 2026-02-18
**Authors**: Verifiable Intent Working Group

## Abstract

This document defines the normative constraint types used in Verifiable Intent
(VI) **Layer 2 Autonomous mode mandates**. Constraints are structured conditions set by
the user that bound an AI agent's delegated authority — restricting what
products it may purchase, which merchants it may transact with, and how much it
may spend.

**Scope:** Constraints apply only to Autonomous mode (3-layer) credentials where the user
delegates authority to an agent. Immediate mode (2-layer) credentials contain final values
directly confirmed by the user and do not use constraints.

This specification covers the schema for each registered constraint type, the
validation algorithm verifiers MUST implement, strictness modes for handling
unknown types, and extensibility rules for adding new constraint types.

For the credential structures in which these constraints appear, see
[credential-format.md](credential-format.md). For the architectural overview
and trust model, see the [Specification Overview](README.md).

### Companion Documents

| Document | Description |
|----------|-------------|
| [Specification Overview](README.md) | Architecture, trust model, design goals |
| [credential-format.md](credential-format.md) | Normative credential format, claim tables, and serialization |
| [security-model.md](security-model.md) | Threat model and security analysis |
| [design-rationale.md](design-rationale.md) | Why SD-JWT, relationship to OpenID4VP/FIDO2/SCA, algorithm choice |
| [glossary.md](../protocol-landscape/glossary.md) | Full glossary with protocol-specific mappings |

---

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119] and [RFC 8174] when, and only when, they
appear in ALL CAPITALS, as shown here.

JSON data structures follow [RFC 8259]. All field names are case-sensitive.
Base64url encoding without padding follows [RFC 4648] §5.

---

## 2. Overview

### 2.1 What Constraints Are

Constraints are structured JSON conditions embedded in **Layer 2 Autonomous mode
mandates** (both checkout mandates and payment mandates) that define the boundaries
within which an AI agent may act on a user's behalf. Each constraint specifies
a verifiable condition that the agent's final actions (captured in Layer 3)
MUST satisfy.

Constraints are the mechanism by which VI converts broad human intent ("buy me
a tennis racket") into cryptographically enforceable limits ("from these SKUs,
at these merchants, for no more than $300").

**Mode distinction:**
- **Autonomous mode (3-layer):** User creates L2 with constraints → Agent creates L3 within those constraints
- **Immediate mode (2-layer):** User creates L2 with final values → No agent, no constraints, no L3

### 2.2 Where Constraints Appear

**Constraints appear ONLY in Autonomous mode credentials.**

In Autonomous mode, constraints appear in the `constraints` array within Layer 2 mandate
disclosures:

- **Checkout mandate** (`vct: "mandate.checkout.open"`): Contains `mandate.checkout.*`
  constraints restricting product selection and merchant access.
- **Payment mandate** (`vct: "mandate.payment.open"`): Contains `payment.*` constraints
  restricting payee selection and amount.

See [credential-format.md](credential-format.md) §4.5.1 and §4.5.2 for the
full mandate payload structures.

**Constraints do NOT appear in Immediate mode credentials** (`vct: "mandate.checkout"` and
`vct: "mandate.payment"`), where the user directly confirms final values rather than
delegating to an agent. Immediate mode mandates contain concrete values (final amounts,
specific items, checkout JWT) rather than constraint objects.

### 2.3 Lifecycle

1. **Creation**: The user constructs constraints at Layer 2 issuance time,
   based on the user's expressed intent and risk preferences.
2. **Binding**: Constraints are included in selectively-disclosable mandate
   claims within Layer 2. In Autonomous mode, the mandates also contain `cnf.jwk` 
   binding the agent's public key, which enables the agent to create Layer 3. 
   The presence of `cnf.jwk` in the mandates (not the constraints themselves) is 
   what makes L2 a KB-SD-JWT+KB (`typ: "kb-sd-jwt+kb"`). The entire L2 credential 
   (including mandates with their constraints and `cnf.jwk`) is signed with the 
   key bound in L1 `cnf.jwk`.
3. **Fulfillment**: The Agent constructs Layer 3 claims containing final
   values (actual SKU selected, actual amount, actual merchant, etc.).
4. **Verification**: The Verifier (merchant or payment network) checks each
   Layer 3 value against its corresponding Layer 2 constraint.

### 2.4 Fulfillment Model

Constraint validation compares Layer 2 constraint objects against a
**fulfillment** — a derived data structure containing resolved final values extracted from
Layer 3 mandates. The fulfillment object is constructed by the verifier from L3 claims
as follows:

| Fulfillment Field | Source in Layer 3 | Extraction Method |
|-------------------|-------------------|-------------------|
| `line_items` | L3b checkout mandate `line_items` array | Direct field extraction |
| `merchant` | Merchant info from `checkout_jwt` inside L3b checkout mandate | Decode and parse the merchant-signed checkout JWT to extract merchant identifier |
| `payee` | L3a payment mandate `payee` object | Direct field extraction: `{id, name, website}` |
| `payment_instrument` | L3a payment mandate `payment_instrument` object | Direct field extraction: `{type, id, description}` |
| `currency` | L3a payment mandate `payment_amount.currency` | Extract from nested object |
| `amount` | L3a payment mandate `payment_amount.amount` | Extract from nested object (integer minor units) |

**Note on merchant extraction:** The `merchant` field in fulfillment is derived by decoding the
`checkout_jwt` string (a merchant-signed JWT) and extracting the merchant identifier from its
payload. The merchant info is not a direct field in the L3 checkout mandate - it's embedded
within the signed checkout JWT. The checkout JWT format and merchant identifier extraction are
defined in [credential-format.md §6.3](credential-format.md#63-checkout_jwt--checkout-object-representation).

**Note on constraint validation:** The validation algorithms in §4 compare these L3-derived fulfillment
values against the corresponding constraints in L2. When validating merchant/payee allowlists,
the verifier also needs the disclosed merchant/payee objects from L2, which are decoded from
the L2 disclosure references separately (not part of the fulfillment structure).

---

## 3. Constraint Structure

### 3.1 Common Schema

Every constraint is a JSON object with a REQUIRED `type` field:

```json
{
  "type": "<domain>.<name>",
  ...additional type-specific fields...
}
```

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Dot-notation identifier for the constraint kind |

The `type` field uses dot-notation where the prefix identifies the
functional area (`mandate.checkout` or `payment`) and the suffix identifies the specific
constraint within that domain.

### 3.2 Unknown Fields

Parsers MUST preserve any fields in a constraint object that they do not
recognize. This enables forward compatibility — a constraint produced by a
newer L2 implementation may contain fields that an older verifier does not yet
understand, but those fields MUST NOT be silently dropped.

### 3.3 Constraints Array

Constraints appear as a JSON array in the mandate claim. A mandate MAY contain
zero or more constraints. (For mode-specific requirements on open mandates, see
[credential-format.md §4](credential-format.md#4-layer-2-user-kb-sd-jwt).)
Multiple constraints of the same type within a single mandate are permitted and
are each validated independently.

**Checkout mandate example:**
```json
{
  "vct": "mandate.checkout.open",
  "constraints": [
    {
      "type": "mandate.checkout.allowed_merchant",
      "allowed_merchants": [...]
    },
    {
      "type": "mandate.checkout.line_items",
      "items": [{"id": "line-1", "acceptable_items": [...], "quantity": 1}]
    }
  ]
}
```

**Payment mandate example:**
```json
{
  "vct": "mandate.payment.open",
  "constraints": [
    {
      "type": "payment.allowed_payee",
      "allowed_payees": [...]
    },
    {
      "type": "payment.amount",
      "currency": "USD",
      "min": 10000,
      "max": 40000
    },
    {
      "type": "payment.reference",
      "conditional_transaction_id": "..."
    }
  ]
}
```

Checkout mandates contain `mandate.checkout.*` constraints; payment mandates contain
`payment.*` constraints. These are separate mandate objects disclosed independently.

---

## 4. Registered Constraint Types

VI defines eight registered constraint types. Verifiers MUST support all
registered types.

### 4.1 `mandate.checkout.allowed_merchant` — Merchant Allowlist

**Purpose**: Restrict which merchants the agent may use for checkout.

**Appears in**: Checkout mandate (`mandate.checkout.open`) `constraints` array.

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"mandate.checkout.allowed_merchant"` |
| `allowed_merchants` | array | Yes | List of approved merchants. Each element is either a merchant object or a selective disclosure reference. |

Each **merchant object** contains:

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `id` | string | No | Unique merchant identifier. When present, used as the primary key for merchant matching. |
| `name` | string | Yes | Display name of the merchant. |
| `website` | string | Yes | URL identifying the merchant. Used for merchant identification when `id` is absent. |

In serialized SD-JWT form, the `allowed_merchants` array MAY contain disclosure
references (`{"...": "<hash>"}`) instead of inline merchant objects. See
[credential-format.md](credential-format.md) §9 for the selective disclosure
mechanism.

#### Validation Algorithm

> **Enforcement dependency:** `allowed_merchant` enforcement requires that `checkout_jwt` contains a machine-readable merchant identifier (`id` field). When `checkout_jwt` does not include a merchant identifier, the constraint cannot be validated. When an `allowed_merchant` constraint is present in the L2 checkout mandate, the `checkout_jwt` MUST include a merchant `id` field — see [credential-format.md §6.3](credential-format.md#63-checkout_jwt--checkout-object-representation) for the conditional MUST requirement.

Given a `mandate.checkout.allowed_merchant` constraint `C` and fulfillment:

1. If `allowed_merchants` is an empty array, reject: **violation** ("Empty
   merchant allowlist is unsatisfiable").
2. Let `disclosed_merchants` be the list of resolved merchant objects from
   the L2 constraint's `allowed_merchants` array (merchants that were disclosed to this verifier).
3. If `disclosed_merchants` is empty, skip this constraint check — the verifier
   cannot validate against merchants it hasn't seen.
4. Extract the merchant identifier from `checkout_jwt` (in the L3b checkout mandate):
   - Decode the `checkout_jwt` JWT
   - Extract merchant `id` from the JWT payload
   - If merchant identifier is not present in the checkout JWT, this constraint cannot be validated
5. Verify that the extracted merchant matches at least one entry from `disclosed_merchants`.
   Matching uses `id` as the primary key when present on both sides; when `id` is absent,
   match by `name` and `website`.
6. If no match is found: **violation** ("Merchant not in allowed list").

> **Note**: Undisclosed merchant references (those remaining as `{"...":
> "<hash>"}`) represent approved merchants whose identity was not revealed to
> this verifier. They do not cause validation failure — the verifier only
> checks against merchants that were actually disclosed.

#### Example (Inline Form)

```json
{
  "type": "mandate.checkout.allowed_merchant",
  "allowed_merchants": [
    { "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com" },
    { "name": "Babolat", "website": "https://babolat.com" }
  ]
}
```

#### Example (SD-JWT Serialized Form)

```json
{
  "type": "mandate.checkout.allowed_merchant",
  "allowed_merchants": [
    { "...": "S2HSMBL-Lye5cYxpCbyGU-TxrDcL-gvvfgOdxfdH3FM" },
    { "...": "NgKlY7bnMEtgVZHQSAcVR5MPGPwtBuFapII8UkYwAjg" }
  ]
}
```

Each hash resolves to a merchant disclosure:

```json
["Tx05iyW-0_n84qEhR7g75Q", { "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com" }]
["nuvTqYrBca0Ra5o-HBDcfw", { "name": "Babolat", "website": "https://babolat.com" }]
```

---

### 4.2 `mandate.checkout.line_items` — Product Selection Constraints

**Purpose**: Restrict which products the agent may include in a purchase and
in what quantities.

**Appears in**: Checkout mandate (`mandate.checkout.open`) `constraints` array.

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"mandate.checkout.line_items"` |
| `items` | array | Yes | Array of line item entries. Each entry defines a line item the agent is authorized to select. |

Each **line item entry** in `items` contains:

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique line item identifier within this constraint. |
| `acceptable_items` | array | Yes | Allowlist of product items for this line item. Each element is either an item object or a selective disclosure reference. The agent MUST only select from these items for this line item. |
| `quantity` | integer | Yes | Maximum quantity for this line item. The quantity selected for this line item MUST NOT exceed this value. |

Each **item object** in `acceptable_items` contains:

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Product identifier (e.g., SKU). Used for matching during validation. |
| `title` | string | Yes | Human-readable product title. Required in the item object schema. |

In serialized SD-JWT form, the `acceptable_items` array within each line item
entry MAY contain disclosure references (`{"...": "<hash>"}`) instead of inline
item objects, enabling selective disclosure of individual product authorizations.

#### Validation Algorithm

Given a `mandate.checkout.line_items` constraint `C` and fulfillment field
`line_items` (extracted from the L3b checkout mandate):

1. If `items` is an empty array, reject: **violation** ("Empty items allowlist
   is unsatisfiable"). `C.items` MUST be non-empty (AP2 schema: `minItems: 1`).
2. Each item entry in `C.items` MUST have an `id` (non-empty string) and an
   `acceptable_items` field (array). For each item object in `acceptable_items`,
   verify that `title` is present. Missing titles are a **violation** (L2
   constraint validation). The `title` provides context for the agent's
   selection process; L3 line items identify by `id` and are not
   required to include `title`.
3. A `line_items` constraint with an empty `items` array is malformed and MUST be treated as
   a **violation** regardless of cart state.
4. Extract `line_items` from the L3b checkout mandate. If `line_items` is empty
   or not present, this is a **violation** ("Empty cart does not satisfy line_items constraint"). Stop.
5. For each item in the L3b `line_items` array:
   a. If `L.acceptable_items` is non-empty for any line item entry `L`: the
      item's `item.id` field MUST appear in the resolved `acceptable_items` for at
      least one line item entry. If not: **violation**. If `L.acceptable_items`
      is empty: any item ID is acceptable for that line item entry (wildcard).
   b. The total quantity selected MUST NOT exceed the sum of all `L.quantity`
      values. If it does: **violation**.
   c. The quantity of any individual SKU MUST NOT exceed the cumulative
      quantity limit derived from line item entries whose `acceptable_items`
      include that SKU. If it does: **violation**.

#### Example

```json
{
  "type": "mandate.checkout.line_items",
  "items": [
    {
      "id": "line-1",
      "acceptable_items": [
        { "id": "BAB86345", "title": "Babolat Pure Aero Tennis Racket" }
      ],
      "quantity": 1
    }
  ]
}
```

This constraint authorizes the agent to select one unit of the Babolat
Pure Aero (BAB86345) tennis racket for line item "line-1".

---

### 4.3 `payment.allowed_payee` — Payee Authorization

**Purpose**: Restrict which payees the agent may direct payment to.

**Appears in**: Payment mandate (`mandate.payment.open`) `constraints` array.

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"payment.allowed_payee"` |
| `allowed_payees` | array | Yes | List of approved payees. Each element is either a payee object or a selective disclosure reference. |

Each **payee object** contains:

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `id` | string | No | Unique payee identifier. When present, used as the primary key for payee matching. |
| `name` | string | Yes | Display name of the payee. |
| `website` | string | Yes | URL identifying the payee. Used for payee identification when `id` is absent. |

In serialized SD-JWT form, the `allowed_payees` array MAY contain disclosure
references (`{"...": "<hash>"}`) instead of inline payee objects. See
[credential-format.md](credential-format.md) §9 for the selective disclosure
mechanism for payee constraints.

#### Validation Algorithm

Given a `payment.allowed_payee` constraint `C` and fulfillment:

1. If `allowed_payees` is an empty array, reject: **violation** ("Empty
   payee allowlist is unsatisfiable").
2. Let `disclosed_payees` be the list of resolved payee objects from the
   L2 constraint's `allowed_payees` array (payees that were disclosed to this verifier).
3. If `disclosed_payees` is empty, skip this constraint check — the verifier
   cannot validate against payees it hasn't seen.
4. Extract the `payee` object from the L3a payment mandate (contains `name`, `website`, and optionally `id`).
5. Verify that the L3a `payee` matches at least one entry from `disclosed_payees`.
   Matching uses `id` as the primary key when present on both sides; when `id` is
   absent, match by `name` and `website`.
6. If no match is found: **violation** ("Payee not in allowed list").

> **Note**: Undisclosed payee references (those remaining as `{"...":
> "<hash>"}`) represent approved payees whose identity was not revealed to
> this verifier. They do not cause validation failure — the verifier only
> checks against payees that were actually disclosed.

#### Example (Inline Form)

```json
{
  "type": "payment.allowed_payee",
  "allowed_payees": [
    { "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com" },
    { "name": "Babolat", "website": "https://babolat.com" }
  ]
}
```

#### Example (SD-JWT Serialized Form)

```json
{
  "type": "payment.allowed_payee",
  "allowed_payees": [
    { "...": "S2HSMBL-Lye5cYxpCbyGU-TxrDcL-gvvfgOdxfdH3FM" },
    { "...": "NgKlY7bnMEtgVZHQSAcVR5MPGPwtBuFapII8UkYwAjg" }
  ]
}
```

Each hash resolves to a payee disclosure:

```json
["Tx05iyW-0_n84qEhR7g75Q", { "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com" }]
["nuvTqYrBca0Ra5o-HBDcfw", { "name": "Babolat", "website": "https://babolat.com" }]
```

---

### 4.4 `payment.amount` — Transaction Amount Range

**Purpose**: Define an acceptable range for the transaction amount the agent
may authorize.

**Appears in**: Payment mandate (`mandate.payment.open`) `constraints` array.

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"payment.amount"` |
| `currency` | string | Yes | ISO 4217 currency code (e.g., `"USD"`) |
| `min` | integer | No | Minimum amount in integer minor units per ISO 4217 (e.g., `10000` = $100.00). If absent, no lower bound. |
| `max` | integer | No | Maximum amount in integer minor units per ISO 4217 (e.g., `40000` = $400.00). If absent, no upper bound. |

> **Amount format**: All monetary amounts in L2 constraints are expressed as integer minor units
> per ISO 4217 (cents for USD, pence for GBP). For example, `27999` represents
> $279.99. The number of fractional digits is defined by the currency's ISO 4217
> minor unit count. Using integers eliminates decimal parsing ambiguity entirely.
> 
> **L3 amount format**: Layer 3 final payment mandates use the same integer minor unit
> format as L2 constraints — `payment_amount.amount` is an integer (e.g., `27999`),
> not a string.

#### Validation Algorithm

Given a `payment.amount` constraint `C` and fulfillment (derived from L3a payment mandate):

1. Extract `payment_amount` object from the L3a payment mandate. If missing: **violation** ("Missing
   payment_amount in L3a payment mandate").
2. Extract `payment_amount.amount` (an integer in minor units). If the value is not a
   valid non-negative integer: **violation** ("Invalid amount format").
3. Extract `payment_amount.currency` (a string).
4. Compare the parsed amount against `C.max`.
   If `amount > C.max`: **violation** ("Amount exceeded: {actual} > {max} {currency}").
5. If `C.min` is present and `amount < C.min`:
   **violation** ("Amount below minimum: {actual} < {min} {currency}").
6. If `currency` does not match `C.currency`:
   **violation** ("Currency mismatch: expected {expected}, got {actual}").

#### Example

```json
{
  "type": "payment.amount",
  "currency": "USD",
  "min": 10000,
  "max": 40000
}
```

An agent purchasing a Babolat Pure Aero at $279.99 (L3 value: `27999`) satisfies
this constraint (10000 <= 27999 <= 40000). An agent attempting to purchase items
totaling $500.00 (L3 value: `50000`) would violate the maximum.

> **Per-transaction scope**: This constraint defines a per-transaction amount range. Each mandate pair is expected to produce exactly one L3, but payment networks MUST enforce this and track cumulative spend across all L3s derived from the same L2 — see [security-model.md §4.2](security-model.md#42-cross-merchant-replay).

---

### 4.5 `payment.budget` — Total Budget Cap

**Purpose**: Define a cumulative spending limit across all transactions executed under
this mandate pair. Used with `payment.agent_recurrence` to cap total spend.

**Appears in**: Payment mandate (`mandate.payment.open`) `constraints` array.

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"payment.budget"` |
| `currency` | string | Yes | ISO 4217 currency code (e.g., `"USD"`) |
| `max` | integer | Yes | Maximum cumulative amount in integer minor units per ISO 4217 (e.g., `50000` = $500.00) |

> **Amount format**: Cumulative budget is expressed as integer minor units
> per ISO 4217 (cents for USD, pence for GBP). For example, `50000` represents
> $500.00 total across all transactions.

#### Validation Algorithm

Given a `payment.budget` constraint `C` and the payment network's tracked state for
this L2 mandate pair:

1. Extract `payment_amount` object from the current L3a payment mandate.
2. Extract `payment_amount.amount` (an integer in minor units).
3. Retrieve `cumulative_spent` from the payment network's mandate tracking state
   (sum of all previously authorized L3a amounts for this mandate pair).
4. Calculate `new_cumulative = cumulative_spent + parsed_amount`.
5. If `new_cumulative > C.max`: **violation** ("Budget exceeded: {new_cumulative} > {max} {currency}").
6. If `payment_amount.currency` does not match `C.currency`:
   **violation** ("Currency mismatch: expected {expected}, got {actual}").

> **Network enforcement**: Payment networks MUST maintain stateful tracking of
> cumulative spend per L2 mandate pair when a `payment.budget` constraint is present.
> See [security-model.md §4.2](security-model.md#42-cross-merchant-replay).

#### Example

```json
{
  "type": "payment.budget",
  "currency": "USD",
  "max": 50000
}
```

This constraint caps total spending at $500.00 across all L3 transactions executed
under the mandate pair containing this constraint.

---

### 4.6 `payment.recurrence` — Merchant-Managed Recurring Payments

**Purpose**: Authorize a merchant to automatically charge the payment instrument on a
recurring basis (e.g., subscriptions, memberships). The merchant manages the recurrence
schedule after the initial setup transaction.

**Appears in**: Payment mandate (`mandate.payment.open`) `constraints` array (Autonomous mode only).

**Use cases**: Netflix subscription, gym membership, newspaper subscription, SaaS billing

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"payment.recurrence"` |
| `frequency` | string | Yes | Recurrence frequency. Valid values: `"DAILY"`, `"WEEKLY"`, `"BIWEEKLY"`, `"MONTHLY"`, `"QUARTERLY"`, `"ANNUALLY"` |
| `start_date` | string | Yes | Start date in ISO 8601 date format (e.g., `"2026-03-01"`) |
| `end_date` | string | RECOMMENDED | End date in ISO 8601 date format. Implementations SHOULD include this to prevent open-ended subscriptions. |
| `number` | integer | RECOMMENDED | Maximum number of recurrences. Implementations SHOULD include this to bound recurring charges. |

> **Semantics**: This constraint authorizes a **subscription setup transaction**. The
> mandate pair is used once to establish the recurring payment relationship with the
> merchant. After setup, the merchant charges the payment instrument automatically
> according to the schedule - no further L3 creation occurs.

> **Network enforcement**: Payment networks SHOULD validate that subscription setup
> transactions include merchant-provided recurrence metadata matching this constraint's
> parameters. The ongoing recurring charges happen outside the VI credential chain.

#### Validation Algorithm

Given a `payment.recurrence` constraint `C` and the L3a payment mandate:

1. Extract merchant-provided recurrence metadata from the payment context (if available).
2. If `frequency` is provided in merchant metadata, verify it matches `C.frequency`.
3. If `start_date` is provided, verify it matches `C.start_date`.
4. If `C.end_date` is present and merchant metadata includes an end date, verify
   the merchant's end date does not exceed `C.end_date`.
5. If `C.number` is present and merchant metadata includes a recurrence count, verify
   the merchant's count does not exceed `C.number`.

> **Note**: In v0.1, merchant recurrence metadata format is implementation-defined.
> Verifiers perform validation only when merchant metadata is available and parseable.

#### Example (Autonomous mode)

```json
{
  "type": "payment.recurrence",
  "frequency": "MONTHLY",
  "start_date": "2026-03-01",
  "end_date": "2027-03-01",
  "number": 12
}
```

This constraint authorizes the agent to set up a monthly subscription starting March 1,
2026, ending March 1, 2027, with a maximum of 12 billing cycles.

---

### 4.7 `payment.agent_recurrence` — Agent-Managed Recurring Purchases

**Purpose**: Authorize an agent to make multiple independent purchases over time within
defined constraints. The agent creates separate L3 pairs for each purchase occurrence.

**Appears in**: Payment mandate (`mandate.payment.open`) `constraints` array.
**Only valid in Autonomous mode.**

**Use cases**: "Book rides to my doctor appointments this month", "Order groceries weekly",
"Buy concert tickets when my favorite artists announce shows"

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"payment.agent_recurrence"` |
| `frequency` | string | Yes | How often agent may make purchases. Valid values: `"ON_DEMAND"` (agent decides timing), `"DAILY"`, `"WEEKLY"`, `"BIWEEKLY"`, `"MONTHLY"`, `"QUARTERLY"`, `"ANNUALLY"` |
| `start_date` | string | Yes | Start date in ISO 8601 date format (e.g., `"2026-03-01"`) |
| `end_date` | string | Yes | End date in ISO 8601 date format. Agent may not create L3s after this date. |
| `max_occurrences` | integer | RECOMMENDED | Maximum number of purchases agent may make. When absent, only `payment.budget` constrains transaction count. |

> **Multi-transaction mandate pairs**: This constraint enables a single L2 mandate pair
> to authorize multiple L3 fulfillments. Each purchase creates a new L3a + L3b pair.
> This extends the base VI model where one mandate pair produces one L3 pair.

> **Required companion constraints**: When `payment.agent_recurrence` is present,
> the payment mandate MUST also include:
> - `payment.amount` (constrains per-transaction amount)
> - `payment.budget` (constrains cumulative spend)

> **Semantics**: The agent creates multiple L3 pairs over time, each representing an
> independent purchase. The `frequency` field guides timing but does not strictly enforce
> it - `ON_DEMAND` gives the agent full discretion; other values suggest a schedule.

#### Validation Algorithm

Given a `payment.agent_recurrence` constraint `C` and the payment network's tracked
state for this L2 mandate pair:

1. Verify current date is between `C.start_date` and `C.end_date` (inclusive).
   If outside range: **violation** ("Agent recurrence period expired or not yet started").
2. Retrieve `occurrence_count` from the payment network's mandate tracking state
   (count of previously authorized L3a transactions for this mandate pair).
3. If `C.max_occurrences` is present and `occurrence_count >= C.max_occurrences`:
   **violation** ("Maximum occurrences exceeded: {count} >= {max}").
4. Verify `payment.amount` constraint is present in the same payment mandate.
   If absent: **violation** ("payment.agent_recurrence requires payment.amount constraint").
5. Verify `payment.budget` constraint is present in the same payment mandate.
   If absent: **violation** ("payment.agent_recurrence requires payment.budget constraint").

> **Note**: The `payment.amount` constraint validates per-transaction limits. The
> `payment.budget` constraint validates cumulative spending. Both are required to
> properly bound agent authority in multi-transaction scenarios.

> **Network enforcement**: Payment networks MUST maintain stateful tracking per L2
> mandate pair when `payment.agent_recurrence` is present:
> - `occurrence_count`: Number of L3a transactions authorized
> - `cumulative_spent`: Total amount across all L3a transactions
> - Enforce `max_occurrences` cap (if present)
> - Enforce `payment.budget` cumulative cap
> - Enforce date range (`start_date` to `end_date`)

See [security-model.md §4.2](security-model.md#42-cross-merchant-replay) for
tracking requirements.

#### Example

```json
{
  "type": "payment.agent_recurrence",
  "frequency": "ON_DEMAND",
  "start_date": "2026-03-01",
  "end_date": "2026-03-31",
  "max_occurrences": 10
}
```

Combined with companion constraints:
```json
{
  "constraints": [
    {
      "type": "payment.agent_recurrence",
      "frequency": "ON_DEMAND",
      "start_date": "2026-03-01",
      "end_date": "2026-03-31",
      "max_occurrences": 10
    },
    {
      "type": "payment.amount",
      "currency": "USD",
      "min": 1000,
      "max": 5000
    },
    {
      "type": "payment.budget",
      "currency": "USD",
      "max": 50000
    }
  ]
}
```

This authorizes the agent to make up to 10 purchases during March 2026, with each
purchase between $10-$50, and total spending capped at $500.

---

### 4.8 `payment.reference` — Checkout-Payment Cross-Reference

**Purpose**: Cryptographically bind a payment mandate to its corresponding
checkout mandate, ensuring the payment constraints apply to a specific checkout
authorization.

**Appears in**: Payment mandate (`mandate.payment.open`) `constraints` array.

#### Schema

| Field | Type | REQUIRED | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | MUST be `"payment.reference"` |
| `conditional_transaction_id` | string | Yes | Base64url-encoded SHA-256 hash of the L2 checkout mandate disclosure string (the base64url-encoded SD-JWT disclosure). This binds the payment mandate to its corresponding checkout mandate at the L2 disclosure level. |

#### Validation

The `payment.reference` constraint is **not validated by the constraint
checker**. Its integrity is verified by the chain verification module, which
recomputes `B64U(SHA-256(ASCII(checkout_disclosure_b64)))` from the L2 checkout
mandate's disclosure string and compares it against `conditional_transaction_id`.

See [credential-format.md](credential-format.md) §6.2 for the related
`checkout_hash` binding mechanism (which operates on `checkout_jwt` at the L3
level, distinct from this L2-level disclosure hash).

#### Example

```json
{
  "type": "payment.reference",
  "conditional_transaction_id": "FtD9HpwqyNCe8lzgn6ta_KahWdS9ElHPFSLbosVV1OY"
}
```

---

## 5. Validation Algorithm

This section defines the normative algorithm for validating a set of
constraints against a fulfillment.

**Empty allowlist principle:** A constraint whose allowlist field is empty MUST
be treated as unsatisfiable. Implementations MUST NOT interpret an empty
allowlist as unrestricted. This applies to: `allowed_merchants` (§4.1),
`allowed_payees` (§4.3), and `items` (§4.2).

### 5.1 Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `constraints` | array of objects | Constraint objects from the Layer 2 mandate |
| `fulfillment` | object | Resolved final values from the Layer 3 mandate (see §2.4) |
| `mode` | enum | Strictness mode: `PERMISSIVE` or `STRICT` (default: `PERMISSIVE`) |
| `is_open_mandate` | boolean | `true` for open (Autonomous) mandate constraints |

### 5.2 Output

The validation algorithm returns a result with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `satisfied` | boolean | `true` if all checked constraints pass; `false` if any violation exists |
| `violations` | string[] | Human-readable descriptions of each constraint violation |
| `checked` | string[] | Constraint types that were successfully validated |
| `skipped` | string[] | Constraint types that were skipped (PERMISSIVE mode only) |

### 5.3 Processing Steps

Verifiers MUST implement the following algorithm:

```
function check_constraints(constraints, fulfillment, mode, is_open_mandate):
    result = { satisfied: true, violations: [], checked: [], skipped: [] }

    for each constraint in constraints:
        ctype = constraint.type

        if ctype is a registered type:
            run type-specific validation (see §4.1–§4.8)
            if violation(s) found:
                append violation message(s) to result.violations
                set result.satisfied = false
            append ctype to result.checked

        else if is_open_mandate:
            append "Unknown constraint type in open mandate: {ctype}" to result.violations
            set result.satisfied = false

        else if mode == STRICT:
            append "Unknown constraint type: {ctype}" to result.violations
            set result.satisfied = false

        else if mode == PERMISSIVE:
            append ctype to result.skipped

    return result
```

Processing MUST continue through all constraints even after encountering a
violation. The `violations` list MUST contain all violations found, not just
the first one.

### 5.4 Strictness Modes

Regardless of strictness mode, verifiers MUST reject open mandates containing
unknown constraint types. An unevaluable constraint in an open mandate leaves
agent authority unbounded — the agent could exploit the unrecognized constraint
to act outside the user's intended scope.

VI defines two strictness modes for constraint validation:

#### PERMISSIVE (Default)

- Unknown constraint types are **skipped** and recorded in the `skipped` list.
- Validation succeeds if all **known** constraint types pass.
- RECOMMENDED for general-purpose verifiers that need forward compatibility
  with newer constraint types.

#### STRICT

- Unknown constraint types cause an immediate **violation**.
- Validation succeeds only if **all** constraint types (including unknown ones)
  are recognized and pass.
- RECOMMENDED for security-critical deployments where unrecognized constraints
  may indicate tampering or version mismatch.

Verifiers MUST support both modes. The default mode MUST be PERMISSIVE.
Deployment configurations MAY override the default to STRICT based on risk
policy.

---

## 6. Extensibility

### 6.1 Custom Constraint Types

Implementations MAY define custom constraint types beyond the eight registered
types in §4. Custom types follow two models:

**Model A: Namespace Extensions** — Extend the registered namespaces with new constraint types:
- `mandate.checkout.*` for checkout mandate constraints
- `payment.*` for payment mandate constraints
- Example: `mandate.checkout.delivery_window`, `payment.installment_plan`
- These extensions follow the same dot-notation pattern as registered types
- Recommended when the constraint fits naturally within the checkout or payment domain

**Model B: Private/Organizational Types** — Use URN or reverse-domain notation:
- Example: `urn:example:loyalty-points`, `com.acme.shipping-preference`
- Recommended for organization-specific constraints that don't fit the checkout/payment model
- Avoids namespace collisions with future registered types

All custom constraint types:
- MUST follow the common schema (§3.1): a JSON object with a `type` field
- Custom constraint types outside the registered eight MUST use collision-resistant
  naming (URN or reverse-DNS). Bare names without namespace qualification risk
  colliding with future registered types.
- MAY use either Model A (namespace extension) or Model B (private naming)

**Namespace Governance:**
- The `mandate.checkout.*` and `payment.*` namespaces are open for extension by implementers
- Namespace extensions within `mandate.checkout.*` or `payment.*` SHOULD be
  proposed for registration to ensure interoperability
- The VI specification maintains a registry of **recommended** constraint types within these namespaces
- Private organizational types that don't require broad interoperability SHOULD use Model B naming

Parsers MUST preserve all fields in constraint objects, including those from
unrecognized types. Silently dropping fields or entire constraint objects
violates this specification.

### 6.2 Constraint Type Registry

The VI specification maintains a registry of constraint types (see
[§6.2](#62-constraint-type-registry)). New types MAY be added to the registry
in future specification versions.

| Type | Defined In | Version | Disclosure Form |
|------|-----------|---------|-----------------|
| `mandate.checkout.allowed_merchant` | This document, §4.1 | 0.1 | array (individual merchants) |
| `mandate.checkout.line_items` | This document, §4.2 | 0.1 | array (individual items) |
| `payment.allowed_payee` | This document, §4.3 | 0.1 | property (full constraint) |
| `payment.amount` | This document, §4.4 | 0.1 | property (full constraint) |
| `payment.budget` | This document, §4.5 | 0.1 | property (full constraint) |
| `payment.recurrence` | This document, §4.6 | 0.1 | property (full constraint) |
| `payment.agent_recurrence` | This document, §4.7 | 0.1 | property (full constraint) |
| `payment.reference` | This document, §4.8 | 0.1 | property (full constraint) |

Verifiers MUST resolve all SD-JWT disclosures before applying constraint schema
validation. For "array" disclosure forms, individual array entries are separate
SD-JWT disclosures referenced by hash from the constraint object. For "property"
disclosure forms, the entire constraint is disclosed or withheld as a unit.

### 6.3 Version Evolution

New constraint types can be added to the registry without breaking existing
verifiers operating in PERMISSIVE mode. Implementations SHOULD:

- Log skipped constraint types so operators can identify when upgrades are
  needed.
- Check the specification version of incoming credentials to detect version
  mismatches.

Deprecated constraint types MUST remain supported for at least two major
specification versions after deprecation to ensure interoperability during
transition periods.

---

## 7. Security Considerations

### 7.1 Amount Range Bypass

Verifiers MUST compare `min` and `max` amount fields as integers. The
specification uses integer minor units per ISO 4217 (e.g., `27999` for $279.99) in L2 constraints, so there is no
decimal parsing ambiguity. Both L2 constraints and L3 final payment mandates use integer minor
units consistently. Verifiers MUST validate that amount values are non-negative integers and
reject any non-integer content.

### 7.2 Item Injection

The `acceptable_items` list within each line item entry of a `mandate.checkout.line_items`
constraint is authoritative and REQUIRED. An agent MUST NOT add items with IDs
not on the list for that line item. An empty `acceptable_items` list means any
item is acceptable for that line item entry (wildcard semantics). L2
implementations SHOULD include a non-empty `acceptable_items` list when they
intend to constrain product selection to specific item IDs.

### 7.3 Payee Manipulation

Payee matching uses `id` as the primary key when present on both the L3a payee
and the disclosed L2 payee objects. When `id` is absent, matching falls back to
`name` and `website` (both REQUIRED). Partial string matching (e.g., substring
or case-insensitive) MUST NOT be used — all comparisons are exact.

### 7.4 Recurrence Abuse

The `payment.recurrence` constraint authorizes merchant-managed subscription setup.
A constraint with `frequency` but no `end_date` or `number` could authorize
indefinite recurring payments. L2 implementations SHOULD set explicit `end_date`
and `number` values to prevent open-ended subscription authorizations. Verifiers
SHOULD warn when these fields are absent.

The `payment.agent_recurrence` constraint mitigates this by requiring `end_date`
(REQUIRED field), preventing open-ended agent-managed recurring purchases.

### 7.5 Constraint Stripping

An attacker who can modify the Layer 2 credential could remove constraints to
expand the agent's authority. This attack is prevented by the KB-SD-JWT+KB signature
on Layer 2 — any modification to the mandate payload (including its
constraints) invalidates the user's signature. Chain verification (see
the [Specification Overview](README.md) §7) detects this.

### 7.6 Unknown Type Exploitation

In PERMISSIVE mode, an attacker could introduce a constraint with an
unrecognized type that a future verifier would enforce but a current verifier
skips. Deployments with high security requirements SHOULD use STRICT mode to
ensure all constraints are understood before accepting a credential.

---

## 8. Examples

### 8.1 Complete Constraint Set (Autonomous Doctor Ride Bookings)

The following example shows the full set of constraints from a Layer 2
autonomous credential authorizing an agent to book rides to doctor appointments
throughout March 2026.

**User instruction**: "Book rides to all my doctor appointments this month, keep
each ride under $50, total budget $500"

**Checkout mandate constraints:**

```json
{
  "constraints": [
    {
      "type": "mandate.checkout.allowed_merchant",
      "allowed_merchants": [
        { "...": "uber-merchant-hash" },
        { "...": "lyft-merchant-hash" }
      ]
    }
  ]
}
```

**Payment mandate constraints:**

```json
{
  "constraints": [
    {
      "type": "payment.allowed_payee",
      "allowed_payees": [
        { "...": "uber-payee-hash" },
        { "...": "lyft-payee-hash" }
      ]
    },
    {
      "type": "payment.amount",
      "currency": "USD",
      "min": 500,
      "max": 5000
    },
    {
      "type": "payment.budget",
      "currency": "USD",
      "max": 50000
    },
    {
      "type": "payment.agent_recurrence",
      "frequency": "ON_DEMAND",
      "start_date": "2026-03-01",
      "end_date": "2026-03-31",
      "max_occurrences": 20
    },
    {
      "type": "payment.reference",
      "conditional_transaction_id": "FtD9HpwqyNCe8lzgn6ta_KahWdS9ElHPFSLbosVV1OY"
    }
  ]
}
```

### 8.1b Complete Constraint Set (Autonomous Tennis Purchase - Original Example)

The following example shows the full set of constraints from a Layer 2
autonomous credential authorizing an agent to purchase a Babolat Pure Aero
tennis racket.

**Checkout mandate constraints:**

```json
{
  "constraints": [
    {
      "type": "mandate.checkout.allowed_merchant",
      "allowed_merchants": [
        { "...": "S2HSMBL-Lye5cYxpCbyGU-TxrDcL-gvvfgOdxfdH3FM" },
        { "...": "NgKlY7bnMEtgVZHQSAcVR5MPGPwtBuFapII8UkYwAjg" }
      ]
    },
    {
      "type": "mandate.checkout.line_items",
      "items": [
        {
          "id": "line-1",
          "acceptable_items": [
            { "...": "item-disclosure-hash-1" }
          ],
          "quantity": 1
        }
      ]
    }
  ]
}
```

**Payment mandate constraints:**

```json
{
  "constraints": [
    {
      "type": "payment.allowed_payee",
      "allowed_payees": [
        { "...": "S2HSMBL-Lye5cYxpCbyGU-TxrDcL-gvvfgOdxfdH3FM" },
        { "...": "NgKlY7bnMEtgVZHQSAcVR5MPGPwtBuFapII8UkYwAjg" }
      ]
    },
    {
      "type": "payment.amount",
      "currency": "USD",
      "min": 10000,
      "max": 40000
    },
    {
      "type": "payment.reference",
      "conditional_transaction_id": "FtD9HpwqyNCe8lzgn6ta_KahWdS9ElHPFSLbosVV1OY"
    }
  ]
}
```

### 8.2 Validation Pass

The agent selects product BAB86345 (Babolat Pure Aero Tennis Racket, $279.99)
from Tennis Warehouse. The Layer 3 mandates contain:

**L3a Payment Mandate:**
```json
{
  "vct": "mandate.payment",
  "payee": {
    "id": "merchant-uuid-1",
    "name": "Tennis Warehouse",
    "website": "https://tennis-warehouse.com"
  },
  "payment_amount": {
    "currency": "USD",
    "amount": 27999
  },
  "payment_instrument": {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234"
  }
}
```

**L3b Checkout Mandate:**
```json
{
  "vct": "mandate.checkout",
  "checkout_jwt": "eyJhbGci...",  // Contains merchant id in decoded payload
  "line_items": [
    {
      "id": "line-item-1",
      "item": {
        "id": "BAB86345",
        "title": "Babolat Pure Aero Tennis Racket"
      },
      "quantity": 1
    }
  ]
}
```

**Result**: All constraints satisfied.

| Constraint | Check | Result |
|-----------|-------|--------|
| `mandate.checkout.allowed_merchant` | Merchant id from decoded `checkout_jwt` matches disclosed merchant | Pass |
| `mandate.checkout.line_items` | Item BAB86345 in acceptable_items, quantity 1 <= 1 | Pass |
| `payment.allowed_payee` | Payee "Tennis Warehouse" matches disclosed payee (by `name` + `website`) | Pass |
| `payment.amount` | Parsed amount 27999 >= 10000 min and <= 40000 max, currency USD matches | Pass |
| `payment.reference` | Verified by chain verification module | Pass |

### 8.3 Validation Failure Examples

#### Amount Exceeded

Agent attempts to purchase items totaling $500.00. L3a payment mandate contains:

```json
{
  "payment_amount": {
    "currency": "USD",
    "amount": 50000
  }
}
```

**Violation**: "Amount exceeded: 50000 > 40000 USD"

#### Amount Below Minimum

Agent attempts to purchase items totaling $50.00. L3a payment mandate contains:

```json
{
  "payment_amount": {
    "currency": "USD",
    "amount": 5000
  }
}
```

**Violation**: "Amount below minimum: 5000 < 10000 USD"

#### Item Not in Acceptable Items

Agent selects product PRI99101 (Prince Synthetic Gut String), which is not in the acceptable items list. L3b checkout mandate contains:

```json
{
  "line_items": [
    {
      "id": "line-item-1",
      "item": {
        "id": "PRI99101",
        "title": "Prince Synthetic Gut String"
      },
      "quantity": 1
    }
  ]
}
```

**Violation**: "Item PRI99101 not in acceptable items list"

#### Payee Not in Allowed List

Agent transacts with an unauthorized payee. L3a payment mandate contains:

```json
{
  "payee": {
    "name": "Unauthorized Store",
    "website": "https://unauthorized-store.example.com"
  }
}
```

**Violation**: "Payee Unauthorized Store not in allowed payees"

---

## 9. References

### Normative References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.

- **[RFC 4648]** Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.

- **[RFC 7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token
  (JWT)", RFC 7519, May 2015.

- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.

- **[RFC 8259]** Bray, T., "The JavaScript Object Notation (JSON) Data
  Interchange Format", STD 90, RFC 8259, December 2017.

- **[SD-JWT]** Fett, D., Yasuda, K., and B. Campbell,
  "Selective Disclosure for JSON Web Tokens (SD-JWT)",
  RFC 9901, November 2025.

- **[FIPS 180-4]** National Institute of Standards and Technology, "Secure
  Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

- **[credential-format.md]** Verifiable Intent Working Group, "Verifiable
  Intent — Credential Format Specification", 2026.

- **[README.md]** Verifiable Intent Working Group, "Verifiable Intent (VI) —
  Specification Overview", 2026.

### Informative References

- **[ISO 4217]** International Organization for Standardization, "Currency
  codes — ISO 4217", 2015.

- **[IEEE 754]** IEEE, "IEEE Standard for Floating-Point Arithmetic",
  IEEE Std 754-2019.
