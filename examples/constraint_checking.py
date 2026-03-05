"""Constraint checking: all v2 registered types + validation modes.

Demonstrates how the Network validates that an agent's fulfillment
(Layer 3) satisfies the user's constraints (Layer 2).

V2 constraint types (8 registered):
  - payment.amount (min/max integer cents)
  - payment.allowed_payee
  - mandate.checkout.allowed_merchant
  - mandate.checkout.line_items
  - payment.reference (conditional_transaction_id)
  - payment.budget (cumulative spend cap)
  - payment.recurrence (merchant-managed subscriptions)
  - payment.agent_recurrence (agent-managed recurring purchases)

Run: python examples/constraint_checking.py
"""

from __future__ import annotations

# Import helpers first — bootstraps sys.path for SDK imports.
from helpers import MERCHANTS, banner, error, step, success, visible
from verifiable_intent.verification.constraint_checker import (
    StrictnessMode,
    check_constraints,
)


def _show_result(label: str, result):
    if result.satisfied:
        visible(label, "SATISFIED")
    else:
        error(f"  {label}: VIOLATED")
        for v in result.violations:
            print(f"      - {v}")
    if result.skipped:
        print(f"      Skipped: {result.skipped}")


def main():
    banner("Constraint Checking — V2 Types")

    # ------------------------------------------------------------------
    # 1. payment.amount — min/max integer cents
    # ------------------------------------------------------------------
    step(1, "payment.amount — Per-transaction budget bounds (integer cents)")

    constraints = [{"type": "payment.amount", "currency": "USD", "min": 10000, "max": 40000}]

    result_pass = check_constraints(
        constraints,
        {"payment_amount": {"amount": 27999, "currency": "USD"}},
    )
    _show_result("27999 cents within 10000-40000 budget", result_pass)
    assert result_pass.satisfied

    result_fail = check_constraints(
        constraints,
        {"payment_amount": {"amount": 45000, "currency": "USD"}},
    )
    _show_result("45000 cents exceeds 40000 max", result_fail)
    assert not result_fail.satisfied

    result_currency = check_constraints(
        constraints,
        {"payment_amount": {"amount": 27999, "currency": "EUR"}},
    )
    _show_result("27999 EUR vs USD budget (currency mismatch)", result_currency)
    assert not result_currency.satisfied

    result_below_min = check_constraints(
        constraints,
        {"payment_amount": {"amount": 5000, "currency": "USD"}},
    )
    _show_result("5000 cents below 10000 min", result_below_min)
    assert not result_below_min.satisfied

    # ------------------------------------------------------------------
    # 2. payment.allowed_payee
    # ------------------------------------------------------------------
    step(2, "payment.allowed_payee — Allowed payees")

    constraints = [
        {
            "type": "payment.allowed_payee",
            "allowed_payees": [
                {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            ],
        }
    ]

    result_with = check_constraints(
        constraints,
        {
            "payee": {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            "allowed_merchants": [
                {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            ],
        },
    )
    _show_result("Payee matches allowed merchant", result_with)
    assert result_with.satisfied

    result_wrong = check_constraints(
        constraints,
        {
            "payee": {"id": "rogue-id", "name": "Rogue Shop", "website": "https://rogue.com"},
            "allowed_merchants": [
                {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
            ],
        },
    )
    _show_result("Payee not in allowed list", result_wrong)
    assert not result_wrong.satisfied

    # ------------------------------------------------------------------
    # 3. mandate.checkout.allowed_merchant
    # ------------------------------------------------------------------
    step(3, "mandate.checkout.allowed_merchant — Merchant allowlist")

    constraints = [
        {
            "type": "mandate.checkout.allowed_merchant",
            "allowed_merchants": MERCHANTS,
        }
    ]

    result_ok = check_constraints(constraints, {})
    _show_result("mandate.checkout.allowed_merchant (structural validation)", result_ok)

    # ------------------------------------------------------------------
    # 4. mandate.checkout.line_items
    # ------------------------------------------------------------------
    step(4, "mandate.checkout.line_items — Allowed products and quantities")

    line_item = {
        "id": "line-item-1",
        "acceptable_items": [{"id": "BAB86345", "title": "Babolat Pure Aero"}],
        "quantity": 1,
    }
    constraints = [{"type": "mandate.checkout.line_items", "items": [line_item]}]

    result_ok = check_constraints(constraints, {})
    _show_result("mandate.checkout.line_items (structural validation)", result_ok)

    # ------------------------------------------------------------------
    # 5. payment.reference — Cross-reference via checkout disclosure hash
    # ------------------------------------------------------------------
    step(5, "payment.reference — Cross-reference via conditional_transaction_id")

    constraints = [{"type": "payment.reference", "conditional_transaction_id": "abc123"}]
    result_ok = check_constraints(constraints, {})
    _show_result("payment.reference (binding checked via integrity layer)", result_ok)

    # ------------------------------------------------------------------
    # Strictness modes
    # ------------------------------------------------------------------
    step(6, "Strictness modes: PERMISSIVE vs STRICT")

    custom_constraints = [
        {"type": "payment.amount", "currency": "USD", "min": 0, "max": 50000},
        {"type": "urn:example:custom-loyalty-check", "loyaltyTier": "gold"},
    ]
    fulfillment = {"payment_amount": {"amount": 10000, "currency": "USD"}}

    result_permissive = check_constraints(
        custom_constraints,
        fulfillment,
        mode=StrictnessMode.PERMISSIVE,
    )
    _show_result("PERMISSIVE mode (unknown types skipped)", result_permissive)
    print(f"      Skipped types: {result_permissive.skipped}")

    result_strict = check_constraints(
        custom_constraints,
        fulfillment,
        mode=StrictnessMode.STRICT,
    )
    _show_result("STRICT mode (unknown types fail)", result_strict)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("""
  +----------------------------------------------------------------+
  |  V2 registered constraint types (8):                           |
  |  -----------------------------------                           |
  |  1. payment.amount               — Min/max cents              |
  |  2. payment.allowed_payee        — Payee allowlist            |
  |  3. mandate.checkout.allowed_merchant — Merchant list         |
  |  4. mandate.checkout.line_items  — Product constraints        |
  |  5. payment.reference            — Checkout cross-ref         |
  |  6. payment.budget               — Cumulative spend cap       |
  |  7. payment.recurrence           — Subscription setup         |
  |  8. payment.agent_recurrence     — Agent recurring purchases  |
  |                                                                |
  |  Extensible: Unknown types handled per strictness mode        |
  |  PERMISSIVE: skip + log   STRICT: reject                      |
  +----------------------------------------------------------------+
""")

    assert result_permissive.satisfied, "Permissive mode should skip unknown types"
    assert not result_strict.satisfied, "Strict mode should fail on unknown types"

    success("Constraint checking demo complete")

    return True


if __name__ == "__main__":
    main()
