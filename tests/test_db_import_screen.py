"""Screening tests for uploaded SQL dumps.

These cover the two findings that both live in `db_admin.screen_import_text`:
a backslash meta-command hidden behind a statement (H-1) and an identity-table
write hidden behind a quoted schema qualifier or an interposed comment (H-2).
Both run on plain text, so no database is touched.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db_admin  # noqa: E402


@pytest.mark.parametrize(
    "sql_text",
    [
        # A meta-command after a complete statement: psql executes it once it
        # reaches the statement boundary, which a line-start-only check missed.
        r"SELECT 1; \! echo pwned",
        r"SELECT 1;\! echo pwned",
        r"SELECT 1; \i /etc/passwd",
        r"SELECT 1; \o /tmp/x",
        # ... and the same trick with the command on the line after the statement.
        "SELECT 1;\n\\! echo pwned\n",
        # COPY ... PROGRAM with the verb appearing anywhere on the line, not only
        # at its start.
        r"/*x*/ COPY (SELECT '') TO PROGRAM 'id';",
        r"SELECT 1; COPY (SELECT '') TO PROGRAM 'id';",
        r"select 1; copy t from program 'id';",
        # Non-allowlisted meta-commands.
        r"\o /tmp/x",
        r"\i /etc/passwd",
        r"\copy t from program 'id'",
    ],
)
def test_meta_command_screen_rejects(sql_text):
    assert db_admin.contains_meta_command(sql_text) is not None


@pytest.mark.parametrize(
    "sql_text",
    [
        # Ordinary pg_dump output must still pass.
        "-- PostgreSQL database dump\n\\restrict abc\n"
        "SET statement_timeout = 0;\n\\unrestrict abc\n",
        # Backslashes inside a COPY payload are data and must not be refused.
        "COPY public.t (a, b) FROM stdin;\n"
        "1\t\\N\n"
        r"2\tsome \\ backslash and \! text" "\n"
        "\\.\n",
        "COPY public.t (a) FROM stdin;\n\\N\n\\.\n",
        # A COPY payload ends properly, so a later statement is still screened.
        "COPY public.t (a) FROM stdin;\n1\n\\.\nSELECT 1;\n",
    ],
)
def test_meta_command_screen_accepts(sql_text):
    assert db_admin.contains_meta_command(sql_text) is None


@pytest.mark.parametrize(
    "sql_text",
    [
        # The forms the audit reproduced as bypasses.
        'UPDATE "public"."admin_accounts" SET capabilities = \'*\';',
        'INSERT INTO "public"."admin_accounts" (username) VALUES (\'x\');',
        'DELETE FROM "public"."admin_accounts";',
        'DROP TABLE "public"."admin_accounts";',
        "INSERT INTO /*c*/ admin_accounts (username) VALUES ('x');",
        # Unquoted forms that already worked, kept as a regression guard.
        "UPDATE admin_accounts SET capabilities = '*';",
        "UPDATE public.admin_accounts SET capabilities = '*';",
        "INSERT INTO admin_accounts (username) VALUES ('x');",
        "DELETE FROM admin_accounts;",
        "DROP TABLE admin_accounts;",
        "TRUNCATE admin_accounts;",
        "COPY admin_accounts FROM stdin;",
        "CREATE INDEX i ON admin_accounts (id);",
        "GRANT SELECT ON admin_accounts TO PUBLIC;",
        # The other protected catalogs.
        "UPDATE pg_authid SET rolpassword = 'x';",
        'SELECT * FROM "public"."pg_shadow";',
    ],
)
def test_protected_table_screen_rejects(sql_text):
    assert db_admin.references_protected_table(sql_text) is not None


@pytest.mark.parametrize(
    "sql_text",
    [
        # A normal application dump.
        "CREATE TABLE public.posts (id bigint);\n"
        "INSERT INTO public.posts (id) VALUES (1);\n"
        "UPDATE public.users SET display_name = 'x';\n",
        # The name appearing as an ordinary column or a longer identifier is not
        # a reference to the identity table.
        "SELECT admin_accounts_count FROM public.users;",
        "INSERT INTO public.admin_accounts_log (id) VALUES (1);",
        # A mention inside a comment is not a statement.
        "-- do not touch admin_accounts here\nSELECT 1;\n",
        "/* UPDATE admin_accounts SET x = 1 */ SELECT 1;\n",
        # Post bodies in a COPY payload are data, even when they contain SQL.
        "COPY public.posts (id, body) FROM stdin;\n"
        "1\tUPDATE admin_accounts SET capabilities = '*'\n"
        "\\.\n",
    ],
)
def test_protected_table_screen_accepts(sql_text):
    assert db_admin.references_protected_table(sql_text) is None


def test_screen_combines_both_checks():
    assert db_admin.screen_import_text("SELECT 1;\n") is None
    assert "元命令" in db_admin.screen_import_text(r"SELECT 1; \! id")
    assert "身份表" in db_admin.screen_import_text("UPDATE admin_accounts SET x = 1;")


def test_restore_credentials_fall_back_to_panel_role(monkeypatch):
    monkeypatch.setattr(db_admin.config, "DB_RESTORE_USER", "")
    monkeypatch.setattr(db_admin.config, "DB_RESTORE_PASSWORD", "")
    user, password = db_admin._restore_credentials()
    assert user == db_admin.config.DB_USER
    assert password == db_admin.config.DB_PASSWORD


def test_restore_credentials_prefer_dedicated_role(monkeypatch):
    monkeypatch.setattr(db_admin.config, "DB_RESTORE_USER", "openfield_restore")
    monkeypatch.setattr(db_admin.config, "DB_RESTORE_PASSWORD", "s3cret")
    user, password = db_admin._restore_credentials()
    assert user == "openfield_restore"
    assert password == "s3cret"
    assert db_admin._common_args(user)[5] == "openfield_restore"
    assert db_admin._pg_env(password)["PGPASSWORD"] == "s3cret"
