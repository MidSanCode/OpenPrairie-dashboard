"""Static checks for the panel's capability model.

The audit (M-2) found destructive and financial routes behind nothing but
@login_required, and a capability edit that changed an account's authority
without writing an audit row. Both are one-line regressions if someone edits a
route by hand, so they are asserted here rather than only in the database-backed
tests, which skip on a machine without a panel database.
"""

import ast
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

APP_SOURCE = os.path.join(REPO_ROOT, "app.py")
TEMPLATE_DIR = os.path.join(REPO_ROOT, "templates")

# Routes the audit found under a bare @login_required, and the capability that
# now has to be held to reach them.
REQUIRED_GATES = {
    "post_delete": "CAP_POSTS_MODERATE",
    "attachment_delete": "CAP_POSTS_MODERATE",
    "user_wallet_history": "CAP_USERS_FINANCE",
    "user_punishment_history": "CAP_USERS_PUNISH",
    "admins": "CAP_ADMINS_MANAGE",
    "admin_capabilities": "CAP_ADMINS_MANAGE",
}


def _source():
    with open(APP_SOURCE, encoding="utf-8") as f:
        return f.read()


def _tree():
    return ast.parse(_source())


def _gated_functions():
    """Map each view function to the capability constant guarding it."""
    gated = {}
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "require_capability"
                and decorator.args
                and isinstance(decorator.args[0], ast.Name)
            ):
                gated[node.name] = decorator.args[0].id
    return gated


def test_destructive_and_financial_routes_are_gated():
    gated = _gated_functions()
    missing = {
        name: cap for name, cap in REQUIRED_GATES.items() if gated.get(name) != cap
    }
    assert not missing, f"routes without the expected capability gate: {missing}"


def test_new_capabilities_are_registerable():
    source = _source()
    capabilities_block = source.split("ALL_CAPABILITIES = (")[1].split(")")[0]
    labels_block = source.split("CAPABILITY_LABELS = {")[1].split("}")[0]
    for constant in ("CAP_POSTS_MODERATE", "CAP_USERS_FINANCE"):
        assert f'{constant} = "' in source, f"{constant} is not defined"
        # A capability missing from ALL_CAPABILITIES cannot be granted through
        # the account form, and one missing from CAPABILITY_LABELS renders as a
        # bare identifier.
        assert constant in capabilities_block, f"{constant} is not in ALL_CAPABILITIES"
        assert constant in labels_block, f"{constant} has no label"


def test_capability_changes_are_audited():
    source = _source()
    assert '"admin.capabilities"' in source, "changing capabilities must be audited"
    assert '"post.delete"' in source, "deleting a post must be audited"
    assert '"attachment.delete"' in source, "deleting an attachment must be audited"


def test_templates_hide_controls_the_account_cannot_use():
    # Hiding is cosmetic — the decorators enforce access — but a button that
    # leads straight to a 403 makes a correctly restricted panel look broken.
    assert "def inject_capabilities" in _source(), "templates need the has_cap helper"
    expectations = {
        "posts.html": "posts.moderate",
        "attachments.html": "posts.moderate",
        "users.html": "users.finance",
        "base.html": "admins.manage",
    }
    for name, capability in expectations.items():
        with open(os.path.join(TEMPLATE_DIR, name), encoding="utf-8") as f:
            text = f.read()
        assert f"has_cap('{capability}')" in text, (
            f"{name} should hide its control behind {capability}"
        )
