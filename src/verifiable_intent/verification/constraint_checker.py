"""Constraint validation: verify Layer 3 values satisfy Layer 2 constraints."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..models.constraints import (
    AgentRecurrenceConstraint,
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
    PaymentBudgetConstraint,
    PaymentRecurrenceConstraint,
    ReferenceConstraint,
    parse_constraint,
)


class StrictnessMode(str, Enum):
    PERMISSIVE = "permissive"  # Skip unknown constraint types
    STRICT = "strict"  # Fail on unknown constraint types


@dataclass
class ConstraintCheckResult:
    satisfied: bool = True
    violations: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def check_constraints(
    constraints: list[dict],
    fulfillment: dict,
    mode: StrictnessMode = StrictnessMode.PERMISSIVE,
    is_open_mandate: bool = False,
) -> ConstraintCheckResult:
    """Check if fulfillment values satisfy all constraints.

    Args:
        constraints: List of constraint dicts from L2 mandate
        fulfillment: Dict of final values from L3 mandate
        mode: PERMISSIVE skips unknown types, STRICT fails on them
        is_open_mandate: If True, unknown constraint types are rejected
            regardless of mode (open mandates leave agent authority unbounded)
    """
    result = ConstraintCheckResult()

    if not isinstance(fulfillment, dict):
        result.satisfied = False
        result.violations.append(f"Fulfillment must be a dict, got {type(fulfillment).__name__}")
        return result
    if not isinstance(constraints, list):
        result.satisfied = False
        result.violations.append(f"Constraints must be a list, got {type(constraints).__name__}")
        return result

    for c_data in constraints:
        if not isinstance(c_data, dict):
            result.satisfied = False
            result.violations.append(f"Constraint entry must be an object, got {type(c_data).__name__}")
            continue
        constraint = parse_constraint(c_data)
        ctype = constraint.type

        if isinstance(constraint, PaymentAmountConstraint):
            _check_payment_amount(constraint, fulfillment, result)
        elif isinstance(constraint, AllowedPayeeConstraint):
            _check_allowed_payee(constraint, fulfillment, result)
        elif isinstance(constraint, AllowedMerchantConstraint):
            _check_allowed_merchant(constraint, fulfillment, result)
        elif isinstance(constraint, CheckoutLineItemsConstraint):
            _check_line_items(constraint, fulfillment, result)
        elif isinstance(constraint, ReferenceConstraint):
            result.checked.append(ctype)  # Reference is checked by integrity module
        elif isinstance(constraint, (PaymentBudgetConstraint, PaymentRecurrenceConstraint, AgentRecurrenceConstraint)):
            result.checked.append(ctype)  # Network-enforced constraints
        else:
            if is_open_mandate or mode == StrictnessMode.STRICT:
                result.satisfied = False
                result.violations.append(f"Unknown constraint type: {ctype}")
            else:
                result.skipped.append(ctype)

    return result


def _merchant_matches(candidate: dict, target: dict) -> bool:
    """Match merchants: by id if both have it, else by name."""
    if not isinstance(candidate, dict) or not isinstance(target, dict):
        return False
    c_id = candidate.get("id")
    t_id = target.get("id")
    if c_id and t_id:
        return c_id == t_id
    return (
        candidate.get("name") == target.get("name")
        and bool(candidate.get("name"))
        and candidate.get("website") == target.get("website")
        and bool(candidate.get("website"))
    )


def _check_payment_amount(c: PaymentAmountConstraint, fulfillment: dict, result: ConstraintCheckResult):
    """Check payment amount is within min/max bounds (integer minor units).

    Per AP2 schema, L3a nests amount/currency under a payment_amount object.
    """
    result.checked.append("payment.amount")
    payment_amount = fulfillment.get("payment_amount")
    if not isinstance(payment_amount, dict) or not payment_amount:
        result.satisfied = False
        result.violations.append("Missing or invalid payment_amount in fulfillment")
        return

    amount_raw = payment_amount.get("amount")
    if amount_raw is None:
        result.satisfied = False
        result.violations.append("Missing amount in fulfillment payment_amount")
        return

    if isinstance(amount_raw, bool) or not isinstance(amount_raw, int):
        result.satisfied = False
        result.violations.append(f"Invalid amount: must be an integer, got {type(amount_raw).__name__}: {amount_raw!r}")
        return
    actual = amount_raw

    if c.min is not None:
        if isinstance(c.min, bool) or not isinstance(c.min, int):
            result.satisfied = False
            result.violations.append(f"Constraint min must be an integer, got {type(c.min).__name__}: {c.min!r}")
            return
        if actual < c.min:
            result.satisfied = False
            result.violations.append(f"Amount below minimum: {actual} < {c.min} {c.currency}")

    if c.max is not None:
        if isinstance(c.max, bool) or not isinstance(c.max, int):
            result.satisfied = False
            result.violations.append(f"Constraint max must be an integer, got {type(c.max).__name__}: {c.max!r}")
            return

        if actual > c.max:
            result.satisfied = False
            result.violations.append(f"Amount exceeds maximum: {actual} > {c.max} {c.currency}")

    fulfillment_currency = payment_amount.get("currency", c.currency)
    if fulfillment_currency != c.currency:
        result.satisfied = False
        result.violations.append(f"Currency mismatch: expected {c.currency}, got {fulfillment_currency}")


def _check_allowed_payee(c: AllowedPayeeConstraint, fulfillment: dict, result: ConstraintCheckResult):
    """Check payee is in the allowed list."""
    result.checked.append("payment.allowed_payee")
    payee = fulfillment.get("payee", {})
    if not isinstance(payee, dict) or not payee:
        result.satisfied = False
        result.violations.append("Missing or invalid payee in fulfillment")
        return

    if not isinstance(c.allowed_payees, list):
        result.satisfied = False
        result.violations.append(
            f"payment.allowed_payee 'allowed_payees' must be a list, got {type(c.allowed_payees).__name__}"
        )
        return
    if not c.allowed_payees:
        result.satisfied = False
        result.violations.append("payment.allowed_payee constraint missing required 'allowed_payees' field")
        return

    # Check if the payee matches any allowed merchant
    # allowed_payees contains SD disclosure refs in L2; fulfillment should have resolved merchants
    allowed_merchants = fulfillment.get("allowed_merchants", [])
    if not isinstance(allowed_merchants, list):
        allowed_merchants = []
    if not allowed_merchants:
        # Support inline allowlists when constraints are not represented as SD refs.
        constraint_allowed = c.allowed_payees if isinstance(c.allowed_payees, list) else []
        allowed_merchants = [
            m for m in constraint_allowed if isinstance(m, dict) and "..." not in m and (m.get("id") or m.get("name"))
        ]
    if not allowed_merchants:
        # Distinguish: all SD refs → skip; inline merchants that failed validation → fail
        source = constraint_allowed if constraint_allowed else c.allowed_payees
        all_sd_refs = all(isinstance(m, dict) and "..." in m for m in source)
        if all_sd_refs:
            result.checked.append("payment.allowed_payee (skipped: no resolved payees)")
            return
        result.satisfied = False
        result.violations.append("allowed_payee constraint present but no payees resolved")
        return

    found = any(_merchant_matches(m, payee) for m in allowed_merchants)
    if not found:
        payee_id = payee.get("id", "")
        result.satisfied = False
        result.violations.append(f"Payee {payee.get('name', '')} (id={payee_id}) not in allowed merchants")


def _check_allowed_merchant(c: AllowedMerchantConstraint, fulfillment: dict, result: ConstraintCheckResult):
    """Check merchant is in the allowed merchant list."""
    result.checked.append("mandate.checkout.allowed_merchant")
    merchant = fulfillment.get("merchant", {})
    if not isinstance(merchant, dict) or not merchant:
        result.satisfied = False
        result.violations.append("Missing or invalid merchant in fulfillment")
        return

    if not isinstance(c.allowed_merchants, list):
        result.satisfied = False
        result.violations.append(
            f"mandate.checkout.allowed_merchant 'allowed_merchants' must be a list, "
            f"got {type(c.allowed_merchants).__name__}"
        )
        return
    if not c.allowed_merchants:
        result.satisfied = False
        result.violations.append(
            "mandate.checkout.allowed_merchant constraint missing required 'allowed_merchants' field"
        )
        return

    allowed_merchants = fulfillment.get("allowed_merchants", [])
    if not isinstance(allowed_merchants, list):
        allowed_merchants = []
    if not allowed_merchants:
        # Support inline allowlists when constraints are not represented as SD refs.
        constraint_merchants = c.allowed_merchants if isinstance(c.allowed_merchants, list) else []
        allowed_merchants = [
            m for m in constraint_merchants if isinstance(m, dict) and "..." not in m and (m.get("id") or m.get("name"))
        ]
    if not allowed_merchants:
        # Distinguish: all SD refs → skip; inline merchants that failed validation → fail
        source = constraint_merchants if constraint_merchants else c.allowed_merchants
        all_sd_refs = all(isinstance(m, dict) and "..." in m for m in source)
        if all_sd_refs:
            result.checked.append("mandate.checkout.allowed_merchant (skipped: no resolved merchants)")
            return
        result.satisfied = False
        result.violations.append("allowed_merchant constraint present but no merchants resolved")
        return

    found = any(_merchant_matches(m, merchant) for m in allowed_merchants)
    if not found:
        merchant_id = merchant.get("id", "")
        result.satisfied = False
        result.violations.append(f"Merchant {merchant.get('name', '')} (id={merchant_id}) not in allowed list")


def _check_line_items(c: CheckoutLineItemsConstraint, fulfillment: dict, result: ConstraintCheckResult):
    """Check selected items match the line items constraint.

    items: list of {id, acceptable_items, quantity} — each defines an allowed
    line item with its own product ID allowlist and quantity limit.
    """
    result.checked.append("mandate.checkout.line_items")

    if not c.items:
        # AP2 schema enforces minItems: 1 on line_items.items — an empty items list
        # is always a malformed constraint regardless of cart state.
        result.satisfied = False
        result.violations.append("line_items constraint must have at least one item entry")
        return

    # L2-side schema validation: acceptable_items entries must have title.
    # This runs regardless of whether line_items are present (constraint validity != fulfillment).
    allowed_ids: set[str] = set()
    id_quantity_limits: dict[str, int] = {}  # item id -> summed quantity cap across matching requirements
    has_nonempty_acceptable = False
    has_wildcard_acceptable = False
    total_quantity_limit = 0
    has_quantity_limit = False

    for item_entry in c.items:
        if not isinstance(item_entry, dict):
            result.satisfied = False
            result.violations.append(f"line_items item entry must be an object, got {type(item_entry).__name__}")
            continue

        acceptable_items = item_entry.get("acceptable_items", [])
        if isinstance(acceptable_items, list) and acceptable_items:
            has_nonempty_acceptable = True
        if isinstance(acceptable_items, list) and not acceptable_items:
            has_wildcard_acceptable = True

        # Validate required fields on each item entry
        item_id = item_entry.get("id")
        if not isinstance(item_id, str) or not item_id:
            result.satisfied = False
            result.violations.append("line_items item entry missing required 'id' field")
            continue
        if "acceptable_items" not in item_entry:
            result.satisfied = False
            result.violations.append(f"line_items item '{item_id}' missing required 'acceptable_items' field")
            continue

        quantity_raw = item_entry.get("quantity")
        if isinstance(quantity_raw, bool) or not isinstance(quantity_raw, int):
            result.satisfied = False
            result.violations.append(f"line_items item quantity must be an integer, got {quantity_raw!r}")
            continue
        quantity_limit = quantity_raw
        if quantity_limit <= 0:
            result.satisfied = False
            result.violations.append("line_items item quantity must be positive")
            continue

        has_quantity_limit = True
        total_quantity_limit += quantity_limit

        if not isinstance(acceptable_items, list):
            result.satisfied = False
            result.violations.append("line_items acceptable_items must be an array")
            continue

        item_ids: set[str] = set()
        for ai in acceptable_items:
            if isinstance(ai, dict) and "..." not in ai:
                if not ai.get("title"):
                    result.satisfied = False
                    result.violations.append(f"Item {ai.get('id', '?')} in acceptable_items missing required 'title'")
                item_id_val = ai.get("id") or ai.get("sku")
                if item_id_val and isinstance(item_id_val, str):
                    item_ids.add(item_id_val)
                    allowed_ids.add(item_id_val)
                elif item_id_val is not None and not isinstance(item_id_val, str):
                    result.satisfied = False
                    result.violations.append(f"acceptable_items entry has non-string id: {type(item_id_val).__name__}")

        for item_id_val in item_ids:
            id_quantity_limits[item_id_val] = id_quantity_limits.get(item_id_val, 0) + quantity_limit

    # Fail-closed: constraint has non-empty acceptable_items, but none resolved to usable IDs.
    # Empty acceptable_items entries are wildcards and allow any item for that line-item requirement.
    if has_nonempty_acceptable and not allowed_ids and not has_wildcard_acceptable:
        result.satisfied = False
        result.violations.append("line_items constraint present but no item IDs resolved")
        return

    line_items = fulfillment.get("line_items", [])
    if not isinstance(line_items, list):
        result.satisfied = False
        result.violations.append(f"line_items must be a list, got {type(line_items).__name__}")
        return
    if not line_items:
        if c.items:
            result.satisfied = False
            result.violations.append("Empty line_items does not satisfy line_items constraint with required items")
        return

    total_quantity = 0
    quantity_by_id: dict[str, int] = {}
    for line_item in line_items:
        if not isinstance(line_item, dict):
            result.satisfied = False
            result.violations.append(f"Line item must be an object, got {type(line_item).__name__}")
            continue
        item_id_val = line_item.get("id") or line_item.get("sku")
        if not item_id_val:
            result.satisfied = False
            result.violations.append("Line item missing 'id' field")
            continue
        if not isinstance(item_id_val, str):
            result.satisfied = False
            result.violations.append(
                f"Line item 'id' must be a non-empty string, got {type(item_id_val).__name__}: {item_id_val!r}"
            )
            continue

        quantity_raw = line_item.get("quantity", 0)
        if isinstance(quantity_raw, bool) or not isinstance(quantity_raw, int):
            result.satisfied = False
            result.violations.append(f"Invalid quantity for item {item_id_val}: {quantity_raw!r}")
            continue
        quantity = quantity_raw
        if quantity < 0:
            result.satisfied = False
            result.violations.append(f"Negative quantity for item {item_id_val}: {quantity}")
            continue

        if allowed_ids and item_id_val and item_id_val not in allowed_ids and not has_wildcard_acceptable:
            result.satisfied = False
            result.violations.append(f"Item {item_id_val} not in acceptable items: {sorted(allowed_ids)}")

        total_quantity += quantity
        if item_id_val:
            quantity_by_id[item_id_val] = quantity_by_id.get(item_id_val, 0) + quantity

    # Aggregate quantity cap across all line-item requirements.
    if has_quantity_limit and total_quantity > total_quantity_limit:
        result.satisfied = False
        result.violations.append(f"Total quantity {total_quantity} exceeds limit {total_quantity_limit}")

    # Per-item quantity caps derived from line-item requirement -> acceptable ID mapping.
    for item_id_val, item_qty in quantity_by_id.items():
        id_cap = id_quantity_limits.get(item_id_val)
        if id_cap is not None and item_qty > id_cap:
            result.satisfied = False
            result.violations.append(f"Quantity for item {item_id_val} exceeds per-item limit {id_cap}")
