"""Read-only access to NetExec's own result databases.

NetExec persists scan results under ~/.nxc/workspaces/<workspace>/<protocol>.db
(SQLite, via SQLAlchemy). Rather than depending on NetExec's internal Python
package (which may not always be importable from the GUI's venv), we read
the SQLite files directly with the stdlib, opened read-only so the GUI can
never corrupt NetExec's own state.

Schema differs slightly per protocol; PRAGMA introspection is used to adapt
to the tables/columns that actually exist instead of hardcoding one schema.
"""
from __future__ import annotations

import configparser
import sqlite3
from pathlib import Path

from app import config
from app.proto_defs import PROTOCOLS_WITH_ADMIN_RELATIONS


def list_workspaces() -> list[str]:
    if not config.NXC_WORKSPACES_DIR.exists():
        return []
    return sorted(p.name for p in config.NXC_WORKSPACES_DIR.iterdir() if p.is_dir())


def get_active_workspace() -> str:
    parser = configparser.ConfigParser()
    parser.read(config.NXC_HOME / "nxc.conf")
    return parser.get("nxc", "workspace", fallback="default")


def _db_path(workspace: str, protocol: str) -> Path:
    if not workspace or Path(workspace).name != workspace:
        raise ValueError("Invalid workspace name")
    root = config.NXC_WORKSPACES_DIR.resolve()
    candidate = (root / workspace / f"{protocol}.db").resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Workspace path escapes the NetExec data directory") from exc
    return candidate


def _open_readonly(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r["name"] for r in rows}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _first_existing(candidates: tuple[str, ...], available: set[str]) -> str | None:
    return next((name for name in candidates if name in available), None)


def get_hosts(workspace: str, protocol: str) -> list[dict]:
    """Returns hosts for a protocol, annotated with pwned status and known credentials."""
    db_path = _db_path(workspace, protocol)
    if not db_path.exists():
        return []

    conn = _open_readonly(db_path)
    try:
        tables = _table_names(conn)
        if "hosts" not in tables:
            return []

        host_cols = _columns(conn, "hosts")
        host_key_col = "ip" if "ip" in host_cols else ("host" if "host" in host_cols else None)
        if host_key_col is None:
            return []

        cred_table = "users" if "users" in tables else ("credentials" if "credentials" in tables else None)
        admin_table = "admin_relations" if "admin_relations" in tables and protocol in PROTOCOLS_WITH_ADMIN_RELATIONS else None
        login_table = "loggedin_relations" if "loggedin_relations" in tables else None

        host_rows = conn.execute("SELECT * FROM hosts").fetchall()

        pwned_host_ids: set[int] = set()
        if admin_table:
            admin_cols = _columns(conn, admin_table)
            admin_host_col = _first_existing(("hostid", "host_id"), admin_cols)
            if admin_host_col:
                for row in conn.execute(f"SELECT DISTINCT {admin_host_col} AS host_id FROM {admin_table}").fetchall():
                    pwned_host_ids.add(row["host_id"])

        shell_host_ids: set[int] = set()
        if login_table:
            login_cols = _columns(conn, login_table)
            login_host_col = _first_existing(("hostid", "host_id"), login_cols)
            shell_col = _first_existing(("shell", "shell_access"), login_cols)
            if login_host_col and shell_col:
                for row in conn.execute(
                    f"SELECT DISTINCT {login_host_col} AS host_id FROM {login_table} WHERE {shell_col} = 1"
                ).fetchall():
                    shell_host_ids.add(row["host_id"])

        creds_by_host: dict[int, list[dict]] = {}
        if cred_table and login_table:
            login_cols = _columns(conn, login_table)
            relation_host_col = _first_existing(("hostid", "host_id"), login_cols)
            relation_cred_col = _first_existing(("userid", "credid", "cred_id"), login_cols)
            join_rows = []
            if relation_host_col and relation_cred_col:
                join_rows = conn.execute(
                    f"""
                    SELECT lr.{relation_host_col} AS relation_host_id, c.*
                    FROM {login_table} lr
                    JOIN {cred_table} c ON c.id = lr.{relation_cred_col}
                    """
                ).fetchall()
            for r in join_rows:
                d = dict(r)
                host_id = d.pop("relation_host_id")
                creds_by_host.setdefault(host_id, []).append({
                    "username": d.get("username"),
                    "domain": d.get("domain"),
                    "password": d.get("password"),
                    "credtype": d.get("credtype"),
                })

        results = []
        for row in host_rows:
            d = dict(row)
            host_id = d.get("id")
            results.append({
                "id": host_id,
                "host": d.get(host_key_col),
                "hostname": d.get("hostname"),
                "domain": d.get("domain"),
                "os": d.get("os"),
                "port": d.get("port"),
                "pwned": host_id in pwned_host_ids,
                "shell_access": host_id in shell_host_ids,
                "credentials": creds_by_host.get(host_id, []),
            })
        return results
    finally:
        conn.close()


def get_pwned_hosts(workspace: str, protocol: str) -> list[dict]:
    return [h for h in get_hosts(workspace, protocol) if h["pwned"]]


def get_backconnect_hosts(workspace: str, protocol: str) -> list[dict]:
    hosts = get_hosts(workspace, protocol)
    if protocol == "ssh":
        return [host for host in hosts if host["pwned"] or host["shell_access"]]
    return [host for host in hosts if host["pwned"]]
