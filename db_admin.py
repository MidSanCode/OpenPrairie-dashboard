"""Database backup/restore helpers for the admin panel.

Uses the PostgreSQL client tools (pg_dump / psql) with credentials from
config.py. Backups are written as plain SQL with --clean/--if-exists so they
can be restored over the current schema, and are stored under admin/backups/.
"""

import os
import re
import shutil
import subprocess
import time

import config

BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")

# Cap the size of error output surfaced in flash messages.
_MAX_ERROR_LEN = 3000

# Backup files are a complete copy of every row in the database, including
# users.password_hash, users.payment_pin_hash, session refresh-token hashes and
# the panel's own admin_accounts rows. They must not be world-readable on disk
# and must not be servable without an explicit capability check.
_BACKUP_FILE_MODE = 0o600


def _restrict_file(path):
    """Best-effort tighten permissions on a file we just created."""
    try:
        os.chmod(path, _BACKUP_FILE_MODE)
    except OSError:
        # Windows / exotic filesystems: not fatal, the capability gate and
        # directory location still protect the file.
        pass

# Largest backup file we will read or import.
MAX_IMPORT_BYTES = 512 * 1024 * 1024

# Identity tables. The restore runs as a database role that owns these tables
# (unless ADMIN_DB_RESTORE_USER points at a restricted one), so a dump
# containing them is a universal privilege-escalation primitive: `UPDATE
# admin_accounts SET can_verify = TRUE` re-grants an account the very permission
# the panel just revoked, and an INSERT there mints a brand-new panel
# administrator. A legitimate data restore has no reason to rewrite the panel's
# own identity rows, so files referencing these tables are refused outright.
# This holds even if the psql meta-command screen is bypassed, because it works
# on the SQL text, not on client syntax.
_PROTECTED_TABLES = (
    "admin_accounts",
    "pg_authid",
    "pg_shadow",
    "pg_roles",
    "pg_auth_members",
)

# Match a table reference in the positions that actually write or read it:
# after CREATE/ALTER/DROP TABLE, INSERT INTO, UPDATE, DELETE FROM, TRUNCATE,
# or COPY ... FROM/TO. A plain substring search would reject an unrelated
# column or comment mentioning the name.
# A schema qualifier, quoted or not: `public.`, `"public".`, `"my schema".`
# The old pattern only accepted `\w+.` or a quoted table name, so
# `UPDATE "public"."admin_accounts"` slipped through — and because the import
# runs as the table owner, that statement could reset a super administrator's
# password hash or mint a new one.
_SCHEMA_QUALIFIER = r'(?:(?:"[^"]*"|[\w$]+)\s*\.\s*)?'

# A protected table name, quoted or not. The bare form stops at a word
# boundary, so `admin_accounts_log` does not match; the quoted form cannot be
# extended at all, which is what makes `"public"."admin_accounts"` match.
_PROTECTED_NAME = (
    r'(?:"(?:' + "|".join(_PROTECTED_TABLES) + r')"'
    r'|(?:' + "|".join(_PROTECTED_TABLES) + r')\b)'
)

# A reference that no legitimate data dump produces: the table is qualified, so
# it is being named explicitly rather than appearing in free text.
_QUALIFIED_PROTECTED_RE = re.compile(
    r'[\w$"]+\s*\.\s*' + _PROTECTED_NAME, re.IGNORECASE
)

# Positions that deliberately name a table: a statement keyword, `ON` (which
# covers CREATE INDEX ... ON, GRANT ... ON and DROP POLICY ... ON), or the DDL
# verb list. Comments are stripped before this runs, so
# `INSERT INTO /*c*/ admin_accounts` no longer hides the reference.
_PROTECTED_TABLE_RE = re.compile(
    r"\b(?:create|alter|drop)\s+"
    r"(?:table|index|sequence|view|trigger|policy|rule|function|procedure)\s+"
    r"(?:if\s+(?:not\s+)?exists\s+)?(?:only\s+)?(?:on\s+)?"
    r"(?:" + _SCHEMA_QUALIFIER + _PROTECTED_NAME + r")"
    r"|\b(?:insert\s+into|delete\s+from|update|copy|truncate|lock|analyze|vacuum|reindex)\s+"
    r"(?:table\s+)?(?:only\s+)?"
    r"(?:" + _SCHEMA_QUALIFIER + _PROTECTED_NAME + r")"
    r"|\bon\s+(?:" + _SCHEMA_QUALIFIER + _PROTECTED_NAME + r")",
    re.IGNORECASE,
)

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"--[^\n]*")

# `COPY ... FROM stdin` starts a data block whose lines are payload, not SQL.
_COPY_FROM_STDIN_RE = re.compile(
    r"^\s*copy\b.*\bfrom\s+stdin\b", re.IGNORECASE | re.DOTALL
)

_NAME_IN_TEXT_RE = re.compile(
    "|".join(_PROTECTED_TABLES), re.IGNORECASE
)


def _strip_comments(sql_text):
    """Remove SQL comments so they cannot split a keyword from its table name."""
    return _LINE_COMMENT_RE.sub(" ", _BLOCK_COMMENT_RE.sub(" ", sql_text))


def _strip_copy_data(sql_text):
    """Drop COPY data payloads: those lines are values, never statements."""
    kept = []
    in_copy_data = False
    for line in sql_text.splitlines():
        if in_copy_data:
            if line.strip() == "\\.":
                in_copy_data = False
            continue
        kept.append(line)
        if _COPY_FROM_STDIN_RE.match(line):
            in_copy_data = True
    return "\n".join(kept)


def references_protected_table(sql_text):
    """Return the identity table a dump touches, or None when it is safe.

    This screens the dump's *statements*: comments and COPY payloads are removed
    first, so a mention of one of these names inside a post body or a comment is
    not mistaken for a write.
    """
    scanned = _strip_copy_data(_strip_comments(sql_text))
    match = _PROTECTED_TABLE_RE.search(scanned) or _QUALIFIED_PROTECTED_RE.search(
        scanned
    )
    if match is None:
        return None
    name = _NAME_IN_TEXT_RE.search(match.group(0))
    return name.group(0).strip('"').lower() if name else "protected identity table"

# psql reads its input the same way it reads an interactive session, so a file
# containing backslash meta-commands executes them: `\!` runs a shell command,
# `\i` includes and runs another file, `\o` writes files, `\copy ... PROGRAM`
# runs a program. Passing a user-uploaded file to `psql -f` therefore handed an
# authenticated admin full command execution on the panel host, with output
# echoed back through the flash message. Only the harmless meta-commands a
# pg_dump-produced script actually emits are allowed through.
_ALLOWED_META = {
    "restrict", "unrestrict", "connect", "encoding", "set", "echo",
    "if", "endif", "on_error_stop", "timing", "charset", "qecho",
}

# Lines starting with a backslash followed by a command word.
_META_RE = re.compile(r"^\\([A-Za-z_][A-Za-z0-9_]*)?")

# `\copy ... PROGRAM '...'` and `COPY ... TO/FROM PROGRAM '...'` execute a
# shell command even though the verb is otherwise legitimate, so they are
# screened separately.
_PROGRAM_RE = re.compile(r"\bPROGRAM\b", re.IGNORECASE)


def contains_meta_command(sql_text):
    """Return a description of the first dangerous construct in sql_text.

    Returns None when the text is safe to feed to psql.

    The previous version only inspected lines that *started* with a backslash,
    which is not how psql reads a script: a meta-command is recognised at the
    start of a statement, so `SELECT 1; \\! id` ran a shell command that the
    screen never looked at. Since the file is passed to `psql -f`, that was
    command execution on the panel host. `--single-transaction` and
    `ON_ERROR_STOP` only constrain the server-side transaction; they do not
    affect the client's parsing.

    The screen is now: inside a COPY payload, backslashes are data; everywhere
    else a backslash is only acceptable as the first character of an allowlisted
    client command. Deliberate trade-off: a bare backslash inside an ordinary SQL
    string literal is also refused. The panel's own exports come from pg_dump and
    never contain one, and refusing is the safe direction.
    """
    in_copy_data = False
    for raw_line in sql_text.splitlines():
        line = raw_line.strip()
        if in_copy_data:
            # The terminator is the only structural line in a data block; every
            # other line is a value and may contain anything, backslashes
            # included.
            if line == "\\.":
                in_copy_data = False
            continue
        if not line:
            continue

        if line.startswith("\\"):
            if line == "\\.":
                continue
            match = _META_RE.match(line)
            cmd = (match.group(1) if match and match.group(1) else "").lower()
            if not cmd:
                # A bare backslash splices the next line onto this one, so psql
                # would read that line's text in this context. Rather than guess
                # at the result, reject it.
                return "\\ (line continuation)"
            if cmd not in _ALLOWED_META:
                return "\\" + cmd
            continue

        # Any backslash outside a COPY payload can begin a meta-command once psql
        # reaches a statement boundary.
        if "\\" in line:
            return "inline backslash"

        if _PROGRAM_RE.search(line) and re.search(r"\bcopy\b", line, re.IGNORECASE):
            return "COPY ... PROGRAM"

        if _COPY_FROM_STDIN_RE.match(line):
            in_copy_data = True

    return None


def _restore_credentials():
    """Role and password used for imports, preferring a dedicated one.

    A restore replays uploaded SQL. When ADMIN_DB_RESTORE_USER is configured the
    import runs as a role without access to the panel's identity tables or to
    server-side program execution, so a screening bypass no longer escalates to
    taking over an administrator. Falls back to the panel's own role, which is
    what every deployment had before this knob existed.
    """
    user = getattr(config, "DB_RESTORE_USER", "") or config.DB_USER
    password = getattr(config, "DB_RESTORE_PASSWORD", "") or config.DB_PASSWORD
    return user, password


def _pg_env(password=None):
    # Hand the child a minimal environment instead of inheriting the panel's.
    #
    # dict(os.environ) gave every psql invocation the panel's ADMIN_SECRET_KEY —
    # the key that signs the session cookie, so holding it means forging an
    # administrator login — along with ADMIN_DB_PASSWORD and anything else the
    # operator happened to export. A child process needs PATH to be found, a
    # locale, and the connection details passed below; psql has no use for the
    # session key and no reason to be able to read it.
    env = {
        key: os.environ[key]
        for key in (
            "PATH",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
        )
        if key in os.environ
    }
    env["PGPASSWORD"] = password if password is not None else config.DB_PASSWORD
    env["PGCLIENTENCODING"] = "UTF8"
    return env


def _common_args(user=None):
    return [
        "-h", config.DB_HOST,
        "-p", str(config.DB_PORT),
        "-U", user or config.DB_USER,
        "-d", config.DB_NAME,
    ]


def _require_tool(name):
    if shutil.which(name) is None:
        raise RuntimeError(
            f"未找到 {name} 命令，请确认 PostgreSQL 客户端已安装并加入 PATH"
        )


def _truncate(text):
    if len(text) <= _MAX_ERROR_LEN:
        return text
    return "..." + text[-(_MAX_ERROR_LEN - 3):]


def _sanitize_error(text):
    """Reduce a tool's stderr to what is safe to show an operator.

    Tool output was rendered into a flash message almost verbatim. It routinely
    contains the filesystem layout, the database host, port and role, and on a
    failure the offending SQL with its literal values — which can include user
    data. The previous pattern also mis-encoded Windows paths (\\\\ in a raw
    string matches two literal backslashes, so single ones were untouched).

    This is a screen, not a redaction guarantee: the goal is that a routine
    failure does not hand out infrastructure detail or row contents, and that a
    short explanatory line survives.
    """
    if not text:
        return ""

    # Connection strings and URLs, which carry host, port, role and password.
    text = re.sub(
        r"\b\w+://[^\s\"']*", "<connection>", text, flags=re.IGNORECASE
    )
    text = re.sub(r"\bPGPASSWORD=\S+", "PGPASSWORD=<hidden>", text)

    # Filesystem paths, POSIX and Windows forms.
    text = re.sub(r"[A-Za-z]:\\[^\s\"'<>|]*", "<path>", text)
    text = re.sub(r"(?<![\w])/(?:[\w.+-]+/)*[\w.+-]+", "<path>", text)

    # Host/port/role/database as psql and libpq phrase them. psql writes these as
    # prose ("connection to server at "HOST", port N failed"), so match the quoted
    # value and the port clause rather than only key=value forms.
    text = re.sub(r'"\s*\d{1,3}(?:\.\d{1,3}){3}\s*"', '"<host>"', text)
    text = re.sub(
        r'\bat\s+"[^"]*"', 'at "<host>"', text, flags=re.IGNORECASE
    )
    text = re.sub(
        r"\bport\s+\d+", "port <hidden>", text, flags=re.IGNORECASE
    )
    text = re.sub(
        r"\b(host|port|user|password|dbname|database)\s*[=:]\s*\S+",
        r"\1=<hidden>",
        text,
        flags=re.IGNORECASE,
    )
    # A bare hostname or IP left anywhere else, e.g. "database \u0022openfield\u0022 on host db.internal".
    text = re.sub(
        r"\b((?:\d{1,3}\.){3}\d{1,3})\b", "<host>", text
    )

    # SQL keywords introducing statements the tool echoed back. Keep a generic
    # note that a statement failed, drop the statement and its literals.
    if re.search(
        r"\b(INSERT|UPDATE|DELETE|SELECT|COPY|ALTER|CREATE|DROP|TRUNCATE)\b",
        text,
        flags=re.IGNORECASE,
    ):
        text = re.sub(
            r"(?is)\b(INSERT|UPDATE|DELETE|SELECT|COPY|ALTER|CREATE|DROP|TRUNCATE)\b.*",
            "（SQL 语句内容已隐藏）",
            text,
            count=1,
        )

    # Collapse repeated whitespace so the flash message stays readable.
    text = re.sub(r"[ \t]{2,}", " ", text).strip()
    return _truncate(text)


def backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return BACKUP_DIR


def list_backups():
    """Return metadata for stored backup files, newest first."""
    if not os.path.isdir(BACKUP_DIR):
        return []
    files = []
    for name in os.listdir(BACKUP_DIR):
        path = os.path.join(BACKUP_DIR, name)
        if os.path.isfile(path):
            st = os.stat(path)
            files.append(
                {
                    "name": name,
                    "size": st.st_size,
                    "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                }
            )
    files.sort(key=lambda f: f["name"], reverse=True)
    return files


def backup_path(filename):
    """Resolve a backup filename inside the backup dir, guarding against traversal.

    Only regular files directly inside BACKUP_DIR are accepted: symlinks are
    rejected rather than resolved, so a link planted in the directory cannot
    turn a download into an arbitrary file read of, say, a private key or the
    panel's own config.py.
    """
    base = os.path.basename(filename)
    if not base or base != filename or base in (".", ".."):
        raise FileNotFoundError(f"备份不存在: {filename}")
    if os.path.islink(os.path.join(BACKUP_DIR, base)):
        raise FileNotFoundError(f"备份不存在: {filename}")
    path = os.path.join(BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"备份不存在: {filename}")
    # Confirm it really lives inside the backup dir after resolution.
    real = os.path.realpath(path)
    if real != path and not real.startswith(os.path.realpath(BACKUP_DIR) + os.sep):
        raise FileNotFoundError(f"备份不存在: {filename}")
    return path


def delete_backup(filename):
    path = backup_path(filename)
    os.remove(path)


def export_backup():
    """Run pg_dump --clean --if-exists and write a timestamped .sql backup.

    Returns (path, message); path is None on failure.
    """
    try:
        _require_tool("pg_dump")
    except RuntimeError as e:
        return None, str(e)

    bdir = backup_dir()
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(bdir, f"openfield-{ts}.sql")

    cmd = [
        "pg_dump",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        *_common_args(),
    ]
    try:
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            result = subprocess.run(
                cmd, stdout=f, stderr=subprocess.PIPE, env=_pg_env(), timeout=1800
            )
    except FileNotFoundError:
        return None, "未找到 pg_dump 命令，请确认 PostgreSQL 客户端已安装并加入 PATH"
    except subprocess.TimeoutExpired:
        try:
            os.remove(out_path)
        except OSError:
            pass
        return None, "备份超时（30 分钟）"

    if result.returncode != 0:
        try:
            os.remove(out_path)
        except OSError:
            pass
        stderr = result.stderr.decode("utf-8", "replace")
        return None, f"备份失败:\n{_truncate(stderr)}"

    size = os.path.getsize(out_path)
    _restrict_file(out_path)
    return out_path, f"备份完成: {os.path.basename(out_path)}（{size / 1024:.1f} KB）"


def screen_import_text(sql_text):
    """Screen a candidate dump. Returns None when safe, else a reason.

    Combining both checks in one place means a call site cannot apply the
    meta-command screen while forgetting the identity-table one.
    """
    bad = contains_meta_command(sql_text)
    if bad is not None:
        return (
            f"备份文件包含不允许的 psql 元命令 {bad}，已拒绝导入。"
            "请仅导入本面板导出的备份文件。"
        )
    protected = references_protected_table(sql_text)
    if protected is not None:
        return (
            f"备份文件试图写入受保护的身份表 {protected}，已拒绝导入。"
            "恢复面板账号不通过数据库导入进行。"
        )
    return None


def read_import_file(sql_path):
    """Read a candidate import file for screening.

    Returns the decoded text, or None when the file is missing, unreadable or
    larger than MAX_IMPORT_BYTES.
    """
    try:
        if os.path.getsize(sql_path) > MAX_IMPORT_BYTES:
            return None
        with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def import_backup(sql_path):
    """Restore a plain-SQL backup via psql inside a single transaction.

    Any failing statement rolls back the whole import, leaving the database
    unchanged. Returns (ok, message).
    """
    try:
        _require_tool("psql")
    except RuntimeError as e:
        return False, str(e)

    # Inspect the script before handing it to psql. This is the last line of
    # defense against the meta-command RCE (see contains_meta_command); the
    # caller screens it too, so a future call site cannot skip the check.
    try:
        size = os.path.getsize(sql_path)
    except OSError as e:
        return False, f"无法读取备份文件: {e}"
    if size > MAX_IMPORT_BYTES:
        return False, f"备份文件过大（{size / 1024 / 1024:.1f} MB），上限 {MAX_IMPORT_BYTES // 1024 // 1024} MB"
    try:
        with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
            sql_text = f.read()
    except OSError as e:
        return False, f"无法读取备份文件: {e}"

    bad = screen_import_text(sql_text)
    if bad is not None:
        return False, bad

    restore_user, restore_password = _restore_credentials()
    cmd = [
        "psql",
        # Do not read ~/.psqlrc: a startup file there would otherwise be
        # executed with the panel's database credentials.
        "-X",
        "--set", "ON_ERROR_STOP=1",
        "--single-transaction",
        *_common_args(restore_user),
        "-f", sql_path,
    ]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_pg_env(restore_password),
            timeout=1800,
        )
    except FileNotFoundError:
        return False, "未找到 psql 命令，请确认 PostgreSQL 客户端已安装并加入 PATH"
    except subprocess.TimeoutExpired:
        return False, "导入超时（30 分钟）"

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace")
        # psql echoes the offending statement and any location it resolved, and
        # a failed import previously surfaced all of it verbatim in the
        # browser. Keep the diagnostic value (the error class and message) but
        # drop absolute paths and DSN-style host/port fragments.
        return False, f"导入失败（已回滚）:\n{_sanitize_error(stderr)}"

    return True, "导入完成（数据已恢复）"
