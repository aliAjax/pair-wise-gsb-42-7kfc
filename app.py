"""Financial-crime investigation and sanctions-screening service."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from difflib import SequenceMatcher
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "financial_crime.db"
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "RU"}
SENSITIVE_ROLES = {"investigator", "supervisor", "director", "auditor"}


class DomainError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_name(value: str) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (value or "").casefold())


def require_role(role: str, allowed: set[str], action: str) -> None:
    if role not in allowed:
        raise DomainError("角色无权执行：%s" % action, 403)


def clean_actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise DomainError("缺少操作人")
    return actor


def name_similarity(left: str, right: str) -> float:
    left, right = normalize_name(left), normalize_name(right)
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()


class FinancialCrimeService:
    def __init__(self, db_path: str | os.PathLike[str] = DEFAULT_DB):
        self.db_path = str(db_path)
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    canonical_name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    aliases TEXT NOT NULL DEFAULT '[]',
                    risk_level TEXT NOT NULL DEFAULT 'low',
                    frozen INTEGER NOT NULL DEFAULT 0,
                    merged_into INTEGER REFERENCES entities(id),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS customers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    customer_no TEXT NOT NULL UNIQUE,
                    country TEXT NOT NULL,
                    occupation TEXT NOT NULL DEFAULT '',
                    allowlisted INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0,
                    merged_into INTEGER REFERENCES customers(id),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    version INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(list_name, normalized_name)
                );
                CREATE TABLE IF NOT EXISTS watchlist_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_no TEXT NOT NULL UNIQUE,
                    list_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    entry_count INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'published',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(list_name, version)
                );
                CREATE TABLE IF NOT EXISTS watchlist_snapshot_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES watchlist_snapshots(id) ON DELETE CASCADE,
                    list_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    active INTEGER NOT NULL DEFAULT 1,
                    position INTEGER NOT NULL,
                    UNIQUE(snapshot_id, normalized_name)
                );
                CREATE TABLE IF NOT EXISTS screening_todos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES watchlist_snapshots(id),
                    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                    case_id INTEGER REFERENCES cases(id),
                    score REAL NOT NULL,
                    match_details TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_by TEXT NOT NULL,
                    resolved_by TEXT,
                    resolved_at TEXT,
                    resolution_note TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(snapshot_id, transaction_id)
                );
                CREATE TRIGGER IF NOT EXISTS watchlist_snapshot_no_update
                BEFORE UPDATE ON watchlist_snapshots
                BEGIN
                    SELECT RAISE(ABORT, '名单快照为不可变档案，禁止改写');
                END;
                CREATE TRIGGER IF NOT EXISTS watchlist_snapshot_no_delete
                BEFORE DELETE ON watchlist_snapshots
                BEGIN
                    SELECT RAISE(ABORT, '名单快照为不可变档案，禁止删除');
                END;
                CREATE TRIGGER IF NOT EXISTS watchlist_entry_no_update
                BEFORE UPDATE ON watchlist_snapshot_entries
                BEGIN
                    SELECT RAISE(ABORT, '名单快照明细为不可变档案，禁止改写');
                END;
                CREATE TRIGGER IF NOT EXISTS watchlist_entry_no_delete
                BEFORE DELETE ON watchlist_snapshot_entries
                BEGIN
                    SELECT RAISE(ABORT, '名单快照明细为不可变档案，禁止删除');
                END;
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txn_ref TEXT NOT NULL UNIQUE,
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL,
                    counterparty_name TEXT NOT NULL,
                    counterparty_country TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    screening_snapshot_id INTEGER REFERENCES watchlist_snapshots(id),
                    screening_version INTEGER,
                    match_details TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    transaction_id INTEGER REFERENCES transactions(id),
                    reason TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    case_id INTEGER,
                    dismissed_reason TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_no TEXT NOT NULL UNIQUE,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    alert_id INTEGER REFERENCES alerts(id),
                    status TEXT NOT NULL DEFAULT 'open',
                    risk_score REAL NOT NULL,
                    assignee TEXT,
                    freeze_target INTEGER NOT NULL DEFAULT 0,
                    report_ref TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    actor TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS entity_merges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER REFERENCES cases(id),
                    entity_id INTEGER REFERENCES entities(id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_txn_entity ON transactions(entity_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, risk_score DESC);
                CREATE INDEX IF NOT EXISTS idx_snapshot_list ON watchlist_snapshots(list_name, version);
                CREATE INDEX IF NOT EXISTS idx_snapshot_entries ON watchlist_snapshot_entries(snapshot_id, normalized_name);
                CREATE INDEX IF NOT EXISTS idx_screening_todos ON screening_todos(status, snapshot_id);
                """
            )
            self._ensure_column(conn, "transactions", "screening_snapshot_id",
                                "INTEGER REFERENCES watchlist_snapshots(id)")
            self._ensure_column(conn, "transactions", "screening_version", "INTEGER")
            self._ensure_column(conn, "transactions", "match_details", "TEXT")
            self._migrate_legacy_watchlist(conn)

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
        if column not in columns:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, definition))

    def _canonical_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not isinstance(entries, list) or not entries:
            raise DomainError("快照必须至少包含一条名单明细")
        normalized_entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, item in enumerate(entries):
            if not isinstance(item, dict):
                raise DomainError("名单明细必须是对象")
            name = str(item.get("name", "")).strip()
            normalized = normalize_name(name)
            if not normalized:
                raise DomainError("第 %d 条名单名称无效" % (index + 1))
            if normalized in seen:
                raise DomainError("快照内存在重复名单名称：%s" % name, 409)
            seen.add(normalized)
            countries = sorted({str(c).strip().upper() for c in (item.get("countries") or []) if str(c).strip()})
            normalized_entries.append({
                "name": name,
                "normalized_name": normalized,
                "countries": countries,
                "active": 1 if item.get("active", True) else 0,
            })
        normalized_entries.sort(key=lambda item: item["normalized_name"])
        return normalized_entries

    def _snapshot_hash(self, list_name: str, entries: list[dict[str, Any]]) -> str:
        payload = {"list_name": list_name, "entries": entries}
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _insert_snapshot(self, conn: sqlite3.Connection, list_name: str, entries: list[dict[str, Any]],
                         actor: str, source: str, version: int | None = None,
                         batch_no: str | None = None) -> sqlite3.Row:
        list_name = list_name.strip()
        if not list_name:
            raise DomainError("名单名称不能为空")
        entries = self._canonical_entries(entries)
        next_version = version
        if next_version is None:
            row = conn.execute(
                "SELECT COALESCE(MAX(version),0)+1 AS version FROM watchlist_snapshots WHERE list_name=?",
                (list_name,),
            ).fetchone()
            next_version = int(row["version"])
        content_hash = self._snapshot_hash(list_name, entries)
        number = (batch_no or "WLS-%s-V%04d" % (list_name, next_version)).strip()
        try:
            cur = conn.execute(
                """INSERT INTO watchlist_snapshots(batch_no,list_name,version,entry_count,content_hash,source,created_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (number, list_name, next_version, len(entries), content_hash, source, actor, utcnow()),
            )
        except sqlite3.IntegrityError as exc:
            raise DomainError("名单批次或版本已存在，不能重复发布", 409) from exc
        for position, entry in enumerate(entries):
            conn.execute(
                """INSERT INTO watchlist_snapshot_entries(snapshot_id,list_name,name,normalized_name,countries,active,position)
                   VALUES(?,?,?,?,?,?,?)""",
                (cur.lastrowid, list_name, entry["name"], entry["normalized_name"],
                 json.dumps(entry["countries"], ensure_ascii=False), entry["active"], position),
            )
        return conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (cur.lastrowid,)).fetchone()

    def _migrate_legacy_watchlist(self, conn: sqlite3.Connection) -> None:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT COUNT(*) AS c FROM watchlist_snapshots").fetchone()["c"]:
            return
        legacy = conn.execute("SELECT * FROM watchlist ORDER BY list_name,id").fetchall()
        if not legacy:
            return
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in legacy:
            grouped.setdefault(row["list_name"], []).append({
                "name": row["name"],
                "normalized_name": row["normalized_name"],
                "countries": json.loads(row["countries"]),
                "active": int(row["active"]),
            })
        migrated: list[dict[str, Any]] = []
        for list_name, entries in grouped.items():
            entries.sort(key=lambda item: item["normalized_name"])
            snapshot = self._insert_snapshot(
                conn, list_name, entries, "system", "legacy_migration", version=1,
                batch_no="WLS-MIGRATION-%s-V0001" % list_name,
            )
            migrated.append({"list_name": list_name, "snapshot_id": snapshot["id"], "entry_count": len(entries)})
        self._audit(conn, "system", "watchlist_snapshot.legacy_migrated", {"snapshots": migrated})

    def _audit(self, conn: sqlite3.Connection, actor: str, action: str, details: dict[str, Any],
               entity_id: int | None = None, case_id: int | None = None) -> None:
        conn.execute(
            "INSERT INTO timeline(case_id,entity_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, entity_id, actor, action, json.dumps(details, ensure_ascii=False, sort_keys=True), utcnow()),
        )

    def _resolve_entity(self, conn: sqlite3.Connection, entity_id: int) -> sqlite3.Row:
        seen = set()
        current = entity_id
        while True:
            if current in seen:
                raise DomainError("实体合并关系存在循环", 409)
            seen.add(current)
            row = conn.execute("SELECT * FROM entities WHERE id=?", (current,)).fetchone()
            if not row:
                raise DomainError("实体不存在", 404)
            if row["merged_into"] is None:
                return row
            current = row["merged_into"]

    def create_entity(self, actor: str, role: str, entity_type: str, canonical_name: str,
                      aliases: list[str] | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator", "supervisor"}, "创建实体")
        entity_type = entity_type.strip().lower()
        canonical_name = canonical_name.strip()
        if entity_type not in {"person", "organization"} or not canonical_name:
            raise DomainError("实体类型或名称无效")
        normalized = normalize_name(canonical_name)
        clean_aliases = sorted({a.strip() for a in (aliases or []) if a and a.strip()}, key=str.casefold)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing_entities = conn.execute(
                "SELECT canonical_name,aliases FROM entities WHERE merged_into IS NULL"
            ).fetchall()
            for row in existing_entities:
                known_names = [row["canonical_name"]] + json.loads(row["aliases"])
                if any(normalize_name(item) == normalized for item in known_names):
                    raise DomainError("实体名称或别名已存在，应使用已有实体或执行合并", 409)
            try:
                cur = conn.execute(
                    """INSERT INTO entities(entity_type,canonical_name,normalized_name,aliases,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (entity_type, canonical_name, normalized, json.dumps(clean_aliases, ensure_ascii=False), actor, utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("实体已存在", 409) from exc
            self._audit(conn, actor, "entity.created", {"name": canonical_name}, cur.lastrowid)
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (cur.lastrowid,)).fetchone())

    def add_alias(self, actor: str, role: str, entity_id: int, alias: str,
                  expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator", "supervisor"}, "维护实体别名")
        alias = alias.strip()
        if not alias:
            raise DomainError("别名不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["merged_into"] is not None:
                raise DomainError("请在主实体上维护别名", 409)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            aliases = json.loads(entity["aliases"])
            normalized = normalize_name(alias)
            conflict = conn.execute(
                "SELECT id,canonical_name,aliases FROM entities WHERE merged_into IS NULL AND id<>?",
                (entity["id"],),
            ).fetchall()
            for row in conflict:
                names = [row["canonical_name"]] + json.loads(row["aliases"])
                if any(normalize_name(name) == normalized for name in names):
                    raise DomainError("别名已属于其他实体，应先执行实体合并", 409)
            if alias not in aliases:
                aliases.append(alias)
                aliases.sort(key=str.casefold)
            conn.execute(
                "UPDATE entities SET aliases=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (json.dumps(aliases, ensure_ascii=False), utcnow(), entity["id"], expected_version),
            )
            self._audit(conn, actor, "entity.alias_added", {"alias": alias}, entity["id"])
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def create_customer(self, actor: str, role: str, entity_id: int, customer_no: str,
                        country: str, occupation: str = "", allowlisted: bool = False,
                        risk_score: float = 0.0) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "supervisor"}, "建立客户档案")
        try:
            risk_score = float(risk_score)
        except (TypeError, ValueError) as exc:
            raise DomainError("风险评分必须是数值") from exc
        if not customer_no.strip() or len(country.strip()) != 2 or not 0 <= risk_score <= 1:
            raise DomainError("客户编号、国家代码或风险评分无效")
        with self.connect() as conn:
            entity = self._resolve_entity(conn, entity_id)
            try:
                cur = conn.execute(
                    """INSERT INTO customers(entity_id,customer_no,country,occupation,allowlisted,risk_score,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (entity["id"], customer_no.strip(), country.strip().upper(), occupation.strip(), int(bool(allowlisted)), risk_score, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("客户编号已存在", 409) from exc
            self._audit(conn, actor, "customer.created", {"customer_no": customer_no.strip()}, entity["id"])
            return dict(conn.execute("SELECT * FROM customers WHERE id=?", (cur.lastrowid,)).fetchone())

    def _snapshot_dict(self, conn: sqlite3.Connection, snapshot: sqlite3.Row,
                       entries: bool = True) -> dict[str, Any]:
        result = dict(snapshot)
        if entries:
            rows = conn.execute(
                "SELECT id,list_name,name,normalized_name,countries,active,position "
                "FROM watchlist_snapshot_entries WHERE snapshot_id=? ORDER BY position,id",
                (snapshot["id"],),
            ).fetchall()
            result["entries"] = [dict(row) for row in rows]
        return result

    def publish_watchlist_snapshot(self, actor: str, role: str, list_name: str,
                                   entries: list[dict[str, Any]],
                                   batch_no: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "发布制裁名单批次")
        if not isinstance(list_name, str):
            raise DomainError("名单名称必须是字符串")
        list_name = list_name.strip()
        entries = self._canonical_entries(entries)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            snapshot = self._insert_snapshot(conn, list_name, entries, actor, "published", batch_no=batch_no)
            conn.execute("DELETE FROM watchlist WHERE list_name=?", (list_name,))
            for entry in entries:
                conn.execute(
                    """INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (list_name, entry["name"], entry["normalized_name"],
                     json.dumps(entry["countries"], ensure_ascii=False), snapshot["version"], entry["active"],
                     actor, snapshot["created_at"]),
                )
            self._audit(
                conn, actor, "watchlist_snapshot.published",
                {"list_name": list_name, "batch_no": snapshot["batch_no"], "version": snapshot["version"],
                 "snapshot_id": snapshot["id"], "entry_count": snapshot["entry_count"], "content_hash": snapshot["content_hash"]},
            )
            return self._snapshot_dict(conn, snapshot)

    def add_or_update_watchlist(self, actor: str, role: str, list_name: str, name: str,
                                countries: list[str] | None = None,
                                active: bool = True, expected_version: int | None = None) -> dict[str, Any]:
        """兼容旧的逐条接口；每次增改都会发布一个完整、不可变的新版本批次。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "维护制裁名单")
        if not isinstance(list_name, str) or not isinstance(name, str):
            raise DomainError("名单名称和实体名称必须是字符串")
        list_name, name = list_name.strip(), name.strip()
        normalized = normalize_name(name)
        if not list_name or not normalized:
            raise DomainError("名单名称和实体名称不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                "SELECT * FROM watchlist WHERE list_name=? ORDER BY id", (list_name,),
            ).fetchall()
            target = conn.execute(
                "SELECT * FROM watchlist WHERE list_name=? AND normalized_name=?", (list_name, normalized)
            ).fetchone()
            if target and expected_version is not None and target["version"] != int(expected_version):
                raise DomainError("名单条目已变化，请刷新后重试", 409)
            entries: list[dict[str, Any]] = []
            replaced = False
            for row in current:
                item_active = int(active) if row["normalized_name"] == normalized else row["active"]
                item_countries = countries if row["normalized_name"] == normalized else json.loads(row["countries"])
                item_name = name if row["normalized_name"] == normalized else row["name"]
                entries.append({"name": item_name, "countries": item_countries, "active": bool(item_active)})
                replaced = replaced or row["normalized_name"] == normalized
            if not target:
                entries.append({"name": name, "countries": countries or [], "active": active})
            snapshot = self._insert_snapshot(conn, list_name, self._canonical_entries(entries), actor, "published")
            conn.execute("DELETE FROM watchlist WHERE list_name=?", (list_name,))
            for entry in self._canonical_entries(entries):
                conn.execute(
                    """INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (list_name, entry["name"], entry["normalized_name"],
                     json.dumps(entry["countries"], ensure_ascii=False), snapshot["version"], entry["active"],
                     actor, snapshot["created_at"]),
                )
            row = conn.execute(
                "SELECT * FROM watchlist WHERE list_name=? AND normalized_name=?", (list_name, normalized)
            ).fetchone()
            self._audit(
                conn, actor, "watchlist.updated" if replaced else "watchlist.added",
                {"list_name": list_name, "name": name, "active": active,
                 "snapshot_id": snapshot["id"], "snapshot_version": snapshot["version"]},
            )
            result = dict(row)
            result["snapshot_id"] = snapshot["id"]
            result["snapshot_version"] = snapshot["version"]
            return result

    def _screen_entries(self, entries: list[sqlite3.Row],
                        counterparty_name: str, country: str) -> tuple[float, sqlite3.Row | None]:
        best_score, best = 0.0, None
        for row in entries:
            matched_countries = json.loads(row["countries"])
            if matched_countries and country.upper() not in matched_countries:
                continue
            score = name_similarity(counterparty_name, row["name"])
            if score > best_score:
                best_score, best = score, row
        return best_score, best

    def _current_watchlist_entries(self, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        return conn.execute(
            """
            SELECT e.*, s.version AS snapshot_version, s.batch_no
            FROM watchlist_snapshot_entries e
            JOIN watchlist_snapshots s ON s.id=e.snapshot_id
            WHERE e.active=1
              AND s.version=(
                  SELECT MAX(s2.version) FROM watchlist_snapshots s2
                  WHERE s2.list_name=s.list_name
              )
            ORDER BY s.list_name, e.position, e.id
        """
        ).fetchall()

    def _screen_against_snapshot(self, conn: sqlite3.Connection, snapshot: sqlite3.Row,
                                 counterparty_name: str, country: str) -> tuple[float, sqlite3.Row | None]:
        entries = conn.execute(
            "SELECT * FROM watchlist_snapshot_entries WHERE snapshot_id=? AND active=1 ORDER BY position,id",
            (snapshot["id"],),
        ).fetchall()
        return self._screen_entries(entries, counterparty_name, country)

    def _latest_snapshot(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM watchlist_snapshots ORDER BY id DESC LIMIT 1").fetchone()

    def ingest_transaction(self, actor: str, role: str, txn_ref: str, customer_id: int,
                           amount: float, currency: str, counterparty_name: str,
                           counterparty_country: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator"}, "录入交易")
        try:
            amount = float(amount)
        except (TypeError, ValueError) as exc:
            raise DomainError("交易金额必须是数值") from exc
        if not txn_ref.strip() or amount <= 0 or len(currency.strip()) != 3 or len(counterparty_country.strip()) != 2:
            raise DomainError("交易编号、金额、币种或国家代码无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            customer = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
            if not customer:
                raise DomainError("客户不存在", 404)
            entity = self._resolve_entity(conn, customer["entity_id"])
            country = counterparty_country.strip().upper()
            counterparty_name = counterparty_name.strip()
            current_entries = self._current_watchlist_entries(conn)
            match_score, matched_entry = self._screen_entries(current_entries, counterparty_name, country)
            match_reason = None
            match_details = None
            if matched_entry and match_score >= 0.9:
                match_score = 0.95
                match_reason = "sanctions_match:%s:%s" % (matched_entry["list_name"], matched_entry["name"])
                match_details = {
                    "snapshot_id": matched_entry["snapshot_id"],
                    "snapshot_version": matched_entry["snapshot_version"],
                    "batch_no": matched_entry["batch_no"],
                    "list_name": matched_entry["list_name"],
                    "entry_name": matched_entry["name"],
                    "normalized_name": matched_entry["normalized_name"],
                    "countries": json.loads(matched_entry["countries"]),
                    "score": match_score,
                }
            base_risk = customer["risk_score"]
            reason = "normal"
            if match_reason:
                risk, reason = max(match_score, base_risk), match_reason
            elif country in HIGH_RISK_COUNTRIES:
                risk, reason = max(0.75, base_risk), "high_risk_country:" + country
            elif amount >= 100000:
                risk, reason = max(0.6, base_risk), "large_value_transaction"
            elif amount >= 50000:
                risk, reason = max(0.35, base_risk), "enhanced_review"
            else:
                risk = base_risk
            if entity["frozen"]:
                status = "blocked"
                reason = "frozen_entity"
                risk = 1.0
            elif match_reason:
                status = "escalated"
            elif risk >= 0.5:
                status = "review"
            else:
                status = "allowed"
            if customer["allowlisted"] and risk < 0.8 and amount <= 200000:
                status, risk, reason = "allowed", min(risk, 0.1), "allowlist_false_positive_reduction"
            try:
                cur = conn.execute(
                    """INSERT INTO transactions(txn_ref,customer_id,entity_id,amount,currency,counterparty_name,
                       counterparty_country,status,risk_score,reason,screening_snapshot_id,screening_version,
                       match_details,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (txn_ref.strip(), customer["id"], entity["id"], amount, currency.strip().upper(),
                     counterparty_name, country, status, risk, reason,
                     matched_entry["snapshot_id"] if matched_entry and match_details else None,
                     matched_entry["snapshot_version"] if matched_entry and match_details else None,
                     json.dumps(match_details, ensure_ascii=False, sort_keys=True) if match_details else None,
                     actor, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("交易编号已存在", 409) from exc
            alert = None
            if status in {"review", "escalated", "blocked"}:
                fingerprint = "%s|%s|%s" % (entity["id"], reason.split(":")[0], normalize_name(counterparty_name))
                existing = conn.execute("SELECT * FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE alerts SET occurrences=occurrences+1,last_seen=?,risk_score=MAX(risk_score,?),transaction_id=? WHERE id=?",
                        (utcnow(), risk, cur.lastrowid, existing["id"]),
                    )
                    alert_id = existing["id"]
                else:
                    alert_cur = conn.execute(
                        """INSERT INTO alerts(fingerprint,entity_id,transaction_id,reason,risk_score,first_seen,last_seen)
                           VALUES(?,?,?,?,?,?,?)""",
                        (fingerprint, entity["id"], cur.lastrowid, reason, risk, utcnow(), utcnow()),
                    )
                    alert_id = alert_cur.lastrowid
                alert = dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            if entity["frozen"]:
                conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status='review'", (entity["id"],))
            self._audit(conn, actor, "transaction.ingested", {"txn_ref": txn_ref, "status": status, "reason": reason}, entity["id"])
            transaction = dict(conn.execute("SELECT * FROM transactions WHERE id=?", (cur.lastrowid,)).fetchone())
            return {"transaction": transaction, "alert": alert, "resolved_entity_id": entity["id"]}

    def _find_case_for_transaction(self, conn: sqlite3.Connection, transaction: sqlite3.Row) -> sqlite3.Row | None:
        direct = conn.execute(
            """
            SELECT c.* FROM cases c
            JOIN alerts a ON a.id=c.alert_id
            WHERE a.transaction_id=?
            ORDER BY c.id DESC LIMIT 1
            """,
            (transaction["id"],),
        ).fetchone()
        if direct:
            return direct
        fingerprint = "%s|%s|%s" % (
            transaction["entity_id"], transaction["reason"].split(":")[0],
            normalize_name(transaction["counterparty_name"]),
        )
        return conn.execute(
            """
            SELECT c.* FROM cases c
            JOIN alerts a ON a.id=c.alert_id
            WHERE a.fingerprint=?
            ORDER BY c.id DESC LIMIT 1
            """,
            (fingerprint,),
        ).fetchone()

    def run_nightly_review(self, actor: str, role: str, snapshot_id: int | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor", "director"}, "执行名单夜间复核")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if snapshot_id is None:
                snapshot = self._latest_snapshot(conn)
                if snapshot is None:
                    raise DomainError("尚无名单快照可用于复核", 409)
            else:
                snapshot = conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (snapshot_id,)).fetchone()
                if not snapshot:
                    raise DomainError("名单快照不存在", 404)
            latest_for_list = conn.execute(
                "SELECT MAX(version) AS version FROM watchlist_snapshots WHERE list_name=?",
                (snapshot["list_name"],),
            ).fetchone()["version"]
            if int(latest_for_list) != int(snapshot["version"]):
                raise DomainError("夜间复核只能使用该名单的最新快照", 409)
            transactions = conn.execute("SELECT * FROM transactions ORDER BY id").fetchall()
            created, existing, skipped, case_records, auto_revoked = [], [], [], [], []
            matched_transaction_ids: set[int] = set()
            for transaction in transactions:
                score, entry = self._screen_against_snapshot(
                    conn, snapshot, transaction["counterparty_name"], transaction["counterparty_country"]
                )
                if not entry or score < 0.9:
                    continue
                matched_transaction_ids.add(transaction["id"])
                duplicate = conn.execute(
                    "SELECT id FROM screening_todos WHERE snapshot_id=? AND transaction_id=?",
                    (snapshot["id"], transaction["id"]),
                ).fetchone()
                if duplicate:
                    existing.append(duplicate["id"])
                    continue
                archived = json.loads(transaction["match_details"]) if transaction["match_details"] else None
                if archived and archived.get("snapshot_id") == snapshot["id"] and archived.get("entry_name") == entry["name"]:
                    skipped.append(transaction["id"])
                    continue
                linked_case = self._find_case_for_transaction(conn, transaction)
                details = {
                    "txn_ref": transaction["txn_ref"],
                    "counterparty_name": transaction["counterparty_name"],
                    "counterparty_country": transaction["counterparty_country"],
                    "snapshot_id": snapshot["id"],
                    "snapshot_version": snapshot["version"],
                    "batch_no": snapshot["batch_no"],
                    "list_name": entry["list_name"],
                    "entry_name": entry["name"],
                    "normalized_name": entry["normalized_name"],
                    "countries": json.loads(entry["countries"]),
                    "score": 0.95,
                    "archived_snapshot_id": transaction["screening_snapshot_id"],
                    "archived_snapshot_version": transaction["screening_version"],
                }
                cur = conn.execute(
                    """INSERT INTO screening_todos(snapshot_id,transaction_id,case_id,score,match_details,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (snapshot["id"], transaction["id"], linked_case["id"] if linked_case else None,
                     0.95, json.dumps(details, ensure_ascii=False, sort_keys=True), actor, utcnow()),
                )
                todo_id = cur.lastrowid
                if linked_case:
                    note = "夜间复核：名单批次 %s（v%s）命中本交易 %s，待办 #%s 已生成；原交易与原线索不变。" % (
                        snapshot["batch_no"], snapshot["version"], transaction["txn_ref"], todo_id
                    )
                    conn.execute(
                        "INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)",
                        (linked_case["id"], actor, note, utcnow()),
                    )
                    case_records.append(linked_case["id"])
                    self._audit(conn, actor, "screening_review.case_appended",
                                {"todo_id": todo_id, "snapshot_id": snapshot["id"], "transaction_id": transaction["id"]},
                                linked_case["entity_id"], linked_case["id"])
                created.append(todo_id)
            stale = conn.execute(
                """
                SELECT t.*, s.list_name FROM screening_todos t
                JOIN watchlist_snapshots s ON s.id=t.snapshot_id
                WHERE t.status='open' AND s.list_name=? AND s.version<?
                """,
                (snapshot["list_name"], snapshot["version"]),
            ).fetchall()
            now = utcnow()
            for todo in stale:
                if todo["transaction_id"] in matched_transaction_ids:
                    continue
                conn.execute(
                    "UPDATE screening_todos SET status='revoked',resolved_by=?,resolved_at=?,resolution_note=? WHERE id=?",
                    (actor, now, "新名单批次 %s v%s 复核后不再命中，自动撤销" % (snapshot["batch_no"], snapshot["version"]), todo["id"]),
                )
                auto_revoked.append(todo["id"])
                if todo["case_id"]:
                    conn.execute(
                        "INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)",
                        (todo["case_id"], actor,
                         "夜间复核：待办 #%s 因新快照 v%s 不再命中而撤销，原交易与原线索不变。" % (todo["id"], snapshot["version"]),
                         now),
                    )
            self._audit(
                conn, actor, "screening_review.completed",
                {"snapshot_id": snapshot["id"], "batch_no": snapshot["batch_no"], "version": snapshot["version"],
                 "created": len(created), "existing": len(existing), "skipped": len(skipped),
                 "case_records": len(case_records), "auto_revoked": len(auto_revoked)},
            )
            return {
                "snapshot": self._snapshot_dict(conn, snapshot, entries=False),
                "created_todo_ids": created,
                "existing_todo_ids": existing,
                "skipped_transaction_ids": skipped,
                "case_record_ids": case_records,
                "auto_revoked_todo_ids": auto_revoked,
                "transactions_reviewed": len(transactions),
            }

    def revoke_screening_todo(self, actor: str, role: str, todo_id: int, note: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor", "director"}, "撤销复核待办")
        note = note.strip()
        if not note:
            raise DomainError("撤销待办必须填写理由")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            todo = conn.execute("SELECT * FROM screening_todos WHERE id=?", (todo_id,)).fetchone()
            if not todo:
                raise DomainError("复核待办不存在", 404)
            if todo["status"] != "open":
                raise DomainError("复核待办已处理，不能重复撤销", 409)
            if role == "investigator" and todo["case_id"]:
                case = conn.execute("SELECT * FROM cases WHERE id=?", (todo["case_id"],)).fetchone()
                if case and case["assignee"] != actor:
                    raise DomainError("待办关联案件仅限被指派调查人员处理", 403)
            now = utcnow()
            conn.execute(
                "UPDATE screening_todos SET status='revoked',resolved_by=?,resolved_at=?,resolution_note=? WHERE id=?",
                (actor, now, note, todo_id),
            )
            if todo["case_id"]:
                case = conn.execute("SELECT * FROM cases WHERE id=?", (todo["case_id"],)).fetchone()
                conn.execute(
                    "INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)",
                    (todo["case_id"], actor, "复核待办 #%s 已撤销：%s；原交易与原线索不变。" % (todo_id, note), now),
                )
                entity_id = case["entity_id"] if case else None
            else:
                entity_id = None
            self._audit(conn, actor, "screening_todo.revoked", {"todo_id": todo_id, "note": note}, entity_id, todo["case_id"])
            return dict(conn.execute("SELECT * FROM screening_todos WHERE id=?", (todo_id,)).fetchone())

    def list_screening_todos(self, actor: str, role: str, status: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看复核待办", 403)
        with self.connect() as conn:
            if status:
                if status not in {"open", "revoked"}:
                    raise DomainError("待办状态无效")
                rows = conn.execute("SELECT * FROM screening_todos WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM screening_todos ORDER BY id DESC").fetchall()
            todos = []
            for row in rows:
                item = dict(row)
                item["match_details"] = json.loads(item["match_details"])
                todos.append(item)
            return {"todos": todos}

    def list_watchlist_snapshots(self, actor: str, role: str, list_name: str | None = None,
                                 include_entries: bool = False) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看名单快照", 403)
        with self.connect() as conn:
            if list_name:
                rows = conn.execute(
                    "SELECT * FROM watchlist_snapshots WHERE list_name=? ORDER BY version DESC", (list_name.strip(),)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM watchlist_snapshots ORDER BY id DESC").fetchall()
            return {"snapshots": [self._snapshot_dict(conn, row, entries=include_entries) for row in rows]}

    def get_watchlist_snapshot(self, actor: str, role: str, snapshot_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看名单快照", 403)
        with self.connect() as conn:
            snapshot = conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if not snapshot:
                raise DomainError("名单快照不存在", 404)
            return {"snapshot": self._snapshot_dict(conn, snapshot)}

    def triage_alert(self, actor: str, role: str, alert_id: int, decision: str,
                    assignee: str | None = None, case_no: str | None = None,
                    reason: str = "") -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "处置可疑线索")
        if decision not in {"dismiss", "escalate"}:
            raise DomainError("线索处置决定无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not alert:
                raise DomainError("线索不存在", 404)
            if alert["status"] not in {"new", "triaged"}:
                raise DomainError("线索已处置", 409)
            if decision == "dismiss":
                if not reason.strip():
                    raise DomainError("误报关闭必须填写理由", 409)
                if alert["risk_score"] >= 0.9:
                    raise DomainError("制裁命中线索不能直接关闭", 409)
                conn.execute("UPDATE alerts SET status='dismissed',dismissed_reason=? WHERE id=?", (reason.strip(), alert_id))
                self._audit(conn, actor, "alert.dismissed", {"alert_id": alert_id, "reason": reason.strip()}, alert["entity_id"])
                return {"alert": dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()), "case": None}
            number = (case_no or "CASE-%06d" % alert_id).strip()
            try:
                cur = conn.execute(
                    """INSERT INTO cases(case_no,entity_id,alert_id,status,risk_score,assignee,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (number, alert["entity_id"], alert_id, "investigating", alert["risk_score"], (assignee or actor).strip(), actor, utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("案件编号已存在", 409) from exc
            conn.execute("UPDATE alerts SET status='case_created',case_id=? WHERE id=?", (cur.lastrowid, alert_id))
            self._audit(conn, actor, "case.created", {"case_no": number, "alert_id": alert_id}, alert["entity_id"], cur.lastrowid)
            return {
                "alert": dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()),
                "case": dict(conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()),
            }

    def _case_access(self, actor: str, role: str, case: sqlite3.Row) -> None:
        if role in {"supervisor", "director", "auditor"}:
            return
        if role == "investigator" and case["assignee"] == actor:
            return
        raise DomainError("案件仅限被指派的调查人员或授权角色访问", 403)

    def update_case(self, actor: str, role: str, case_id: int, note: str,
                    expected_version: int, status: str | None = None,
                    assignee: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "更新案件")
        if not note.strip():
            raise DomainError("调查记录不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            self._case_access(actor, role, case)
            if case["version"] != int(expected_version):
                raise DomainError("案件已变化，请刷新后重试", 409)
            if case["status"] in {"closed", "report_filed"} and role != "supervisor":
                raise DomainError("已结束案件不能再更新", 409)
            new_status = status or case["status"]
            if new_status not in {"open", "investigating", "escalated", "closed", "report_filed"}:
                raise DomainError("案件状态无效")
            if role == "investigator" and new_status in {"closed", "report_filed"}:
                raise DomainError("调查员不能自行结束案件", 403)
            conn.execute("INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)", (case_id, actor, note.strip(), utcnow()))
            conn.execute(
                "UPDATE cases SET status=?,assignee=COALESCE(?,assignee),version=version+1,updated_at=? WHERE id=? AND version=?",
                (new_status, assignee.strip() if assignee else None, utcnow(), case_id, expected_version),
            )
            self._audit(conn, actor, "case.updated", {"status": new_status, "note": note.strip()}, case["entity_id"], case_id)
            return dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())

    def freeze_entity(self, actor: str, role: str, entity_id: int, reason: str,
                      expected_version: int, case_id: int | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor", "director"}, "冻结实体")
        if not reason.strip():
            raise DomainError("冻结原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            conn.execute("UPDATE entities SET frozen=1,risk_level='high',version=version+1,updated_at=? WHERE id=?", (utcnow(), entity["id"]))
            conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status IN ('review','allowed')", (entity["id"],))
            if case_id is not None:
                case = conn.execute("SELECT * FROM cases WHERE id=? AND entity_id=?", (case_id, entity["id"])).fetchone()
                if not case:
                    raise DomainError("案件与实体不匹配", 409)
                conn.execute(
                    "UPDATE cases SET freeze_target=1,status=CASE WHEN status='investigating' THEN 'escalated' ELSE status END,version=version+1,updated_at=? WHERE id=?",
                    (utcnow(), case_id),
                )
            self._audit(conn, actor, "entity.frozen", {"reason": reason.strip()}, entity["id"], case_id)
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def unfreeze_entity(self, actor: str, role: str, entity_id: int, reason: str,
                        expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"director"}, "解除冻结")
        if not reason.strip():
            raise DomainError("解冻原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            conn.execute("UPDATE entities SET frozen=0,risk_level='medium',version=version+1,updated_at=? WHERE id=?", (utcnow(), entity["id"]))
            self._audit(conn, actor, "entity.unfrozen", {"reason": reason.strip()}, entity["id"])
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def merge_entities(self, actor: str, role: str, source_id: int, target_id: int,
                       source_version: int, target_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "合并实体")
        if source_id == target_id:
            raise DomainError("不能合并同一实体")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            source = self._resolve_entity(conn, source_id)
            target = self._resolve_entity(conn, target_id)
            if source["version"] != int(source_version) or target["version"] != int(target_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            if source["id"] == target["id"]:
                raise DomainError("实体已经合并到目标", 409)
            source_aliases = json.loads(source["aliases"])
            target_aliases = json.loads(target["aliases"])
            aliases = sorted(set(target_aliases + source_aliases + [source["canonical_name"]]), key=str.casefold)
            now = utcnow()
            conn.execute(
                """UPDATE entities SET aliases=?,frozen=MAX(frozen,?),risk_level=?,version=version+1,updated_at=?
                   WHERE id=?""",
                (json.dumps(aliases, ensure_ascii=False), source["frozen"],
                 "high" if source["frozen"] or target["frozen"] else max(source["risk_level"], target["risk_level"], key=lambda x: {"low": 0, "medium": 1, "high": 2}.get(x, 0)),
                 now, target["id"]),
            )
            conn.execute("UPDATE entities SET merged_into=?,version=version+1,updated_at=? WHERE id=?", (target["id"], now, source["id"]))
            conn.execute("UPDATE customers SET entity_id=?,version=version+1 WHERE entity_id=? AND merged_into IS NULL", (target["id"], source["id"]))
            conn.execute("UPDATE transactions SET entity_id=? WHERE entity_id=?", (target["id"], source["id"]))
            conn.execute("UPDATE alerts SET entity_id=? WHERE entity_id=?", (target["id"], source["id"]))
            conn.execute("UPDATE cases SET entity_id=?,version=version+1,updated_at=? WHERE entity_id=?", (target["id"], now, source["id"]))
            details = {"source": source["canonical_name"], "target": target["canonical_name"], "aliases": aliases}
            conn.execute(
                "INSERT INTO entity_merges(source_id,target_id,actor,details,created_at) VALUES(?,?,?,?,?)",
                (source["id"], target["id"], actor, json.dumps(details, ensure_ascii=False), now),
            )
            self._audit(conn, actor, "entity.merged", details, target["id"])
            return {"source": dict(conn.execute("SELECT * FROM entities WHERE id=?", (source["id"],)).fetchone()),
                    "target": dict(conn.execute("SELECT * FROM entities WHERE id=?", (target["id"],)).fetchone())}

    def file_report(self, actor: str, role: str, case_id: int, report_ref: str,
                    expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "提交监管报告")
        if not report_ref.strip():
            raise DomainError("监管报告编号不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            if case["version"] != int(expected_version):
                raise DomainError("案件已变化，请刷新后重试", 409)
            if case["status"] not in {"investigating", "escalated"}:
                raise DomainError("当前案件状态不能提交监管报告", 409)
            if case["risk_score"] < 0.5:
                raise DomainError("低风险案件不需要监管报告", 409)
            conn.execute(
                "UPDATE cases SET status='report_filed',report_ref=?,version=version+1,updated_at=? WHERE id=?",
                (report_ref.strip(), utcnow(), case_id),
            )
            self._audit(conn, actor, "case.report_filed", {"report_ref": report_ref.strip()}, case["entity_id"], case_id)
            return dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())

    def get_case(self, actor: str, role: str, case_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看案件", 403)
        with self.connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            self._case_access(actor, role, case)
            notes = [dict(r) for r in conn.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
            return {"case": dict(case), "notes": notes}

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        if role not in SENSITIVE_ROLES:
            return {"entities": [], "transactions": [], "alerts": [], "cases": [], "timeline": [], "access_limited": True}
        with self.connect() as conn:
            if role == "investigator":
                cases = [dict(r) for r in conn.execute("SELECT * FROM cases WHERE assignee=? ORDER BY id DESC", (actor,)).fetchall()]
            else:
                cases = [dict(r) for r in conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()]
            entities = [dict(r) for r in conn.execute("SELECT * FROM entities ORDER BY id DESC LIMIT 100").fetchall()]
            transactions = [dict(r) for r in conn.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 100").fetchall()]
            case_ids = [c["id"] for c in cases]
            if role == "investigator" and case_ids:
                marks = ",".join("?" for _ in case_ids)
                alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE case_id IN (%s) ORDER BY id DESC LIMIT 100" % marks, case_ids).fetchall()]
            elif role == "investigator":
                alerts = []
            else:
                alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()]
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline ORDER BY id DESC LIMIT 200").fetchall()]
            snapshots = [dict(r) for r in conn.execute(
                "SELECT * FROM watchlist_snapshots ORDER BY id DESC LIMIT 100"
            ).fetchall()]
            todo_rows = [dict(r) for r in conn.execute(
                "SELECT * FROM screening_todos ORDER BY id DESC LIMIT 100"
            ).fetchall()]
            for todo in todo_rows:
                todo["match_details"] = json.loads(todo["match_details"])
        return {
            "entities": entities,
            "transactions": transactions,
            "alerts": alerts,
            "cases": cases,
            "timeline": timeline,
            "watchlist_snapshots": snapshots,
            "screening_todos": todo_rows,
            "access_limited": False,
        }

    def seed_demo(self) -> dict[str, Any]:
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) AS c FROM entities").fetchone()["c"]:
                return {"seeded": False, "reason": "已有数据"}
        entity = self.create_entity("analyst-demo", "analyst", "organization", "海岳贸易有限公司", ["海岳贸易"])
        customer = self.create_customer("analyst-demo", "analyst", entity["id"], "CUST-0001", "CN", "贸易", False, 0.2)
        self.add_or_update_watchlist("sup-demo", "supervisor", "OFAC", "海岳贸易有限公司", ["CN"])
        result = self.ingest_transaction("analyst-demo", "analyst", "TXN-DEMO-0001", customer["id"], 150000, "USD", "海岳贸易有限公司", "CN")
        return {"seeded": True, "entity_id": entity["id"], "customer_id": customer["id"], "alert_id": result["alert"]["id"] if result["alert"] else None}


class ApiHandler(BaseHTTPRequestHandler):
    service: FinancialCrimeService

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _headers(self) -> tuple[str, str]:
        return self.headers.get("X-User", ""), self.headers.get("X-Role", "viewer")

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise DomainError("请求体过大", 413)
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DomainError("请求体不是有效 JSON") from exc
        if not isinstance(value, dict):
            raise DomainError("JSON 请求体必须是对象")
        return value

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path in {"/", "/index.html"}:
                body = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            actor, role = self._headers()
            if path == "/health":
                self._send(200, {"status": "ok", "service": "financial-crime"})
            elif path == "/api/state":
                self._send(200, self.service.state(actor, role))
            elif path == "/api/watchlist/snapshots":
                query = urlparse(self.path).query
                params = dict(item.split("=", 1) for item in query.split("&") if item and "=" in item)
                self._send(200, self.service.list_watchlist_snapshots(
                    actor, role, params.get("list_name"), params.get("include_entries") in {"1", "true", "yes"}
                ))
            elif path == "/api/screening/todos":
                query = urlparse(self.path).query
                status = None
                if query:
                    for item in query.split("&"):
                        if item.startswith("status="):
                            status = item.split("=", 1)[1]
                self._send(200, self.service.list_screening_todos(actor, role, status))
            elif path.startswith("/api/watchlist/snapshots/"):
                self._send(200, self.service.get_watchlist_snapshot(actor, role, int(path.split("/")[4])))
            elif path.startswith("/api/cases/"):
                self._send(200, self.service.get_case(actor, role, int(path.split("/")[3])))
            else:
                self._send(404, {"error": "接口不存在"})
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (ValueError, IndexError) as exc:
            self._send(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            path, data, (actor, role) = urlparse(self.path).path, self._json(), self._headers()
            if path == "/api/entities":
                result = self.service.create_entity(actor, role, **data)
            elif path == "/api/entities/alias":
                result = self.service.add_alias(actor, role, **data)
            elif path == "/api/customers":
                result = self.service.create_customer(actor, role, **data)
            elif path == "/api/watchlist":
                result = self.service.add_or_update_watchlist(actor, role, **data)
            elif path == "/api/watchlist/snapshots":
                result = self.service.publish_watchlist_snapshot(actor, role, **data)
            elif path == "/api/screening/review":
                result = self.service.run_nightly_review(actor, role, **data)
            elif path == "/api/screening/todos/revoke":
                result = self.service.revoke_screening_todo(actor, role, **data)
            elif path == "/api/transactions":
                result = self.service.ingest_transaction(actor, role, **data)
            elif path == "/api/alerts/triage":
                result = self.service.triage_alert(actor, role, **data)
            elif path == "/api/cases/update":
                result = self.service.update_case(actor, role, **data)
            elif path == "/api/entities/freeze":
                result = self.service.freeze_entity(actor, role, **data)
            elif path == "/api/entities/unfreeze":
                result = self.service.unfreeze_entity(actor, role, **data)
            elif path == "/api/entities/merge":
                result = self.service.merge_entities(actor, role, **data)
            elif path == "/api/cases/report":
                result = self.service.file_report(actor, role, **data)
            else:
                raise DomainError("接口不存在", 404)
            self._send(201, result)
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            self._send(400, {"error": "请求参数错误: %s" % exc})
        except Exception as exc:
            self._send(500, {"error": "服务器内部错误", "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def serve(service: FinancialCrimeService, host: str, port: int) -> None:
    ApiHandler.service = service
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print("Financial crime service listening on http://%s:%s" % (host, port))
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="金融犯罪调查与制裁筛查服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8208)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    service = FinancialCrimeService(args.db)
    if args.init:
        print(json.dumps(service.seed_demo() if args.seed else {"initialized": True, "db": args.db}, ensure_ascii=False))
        return
    serve(service, args.host, args.port)


if __name__ == "__main__":
    main()
