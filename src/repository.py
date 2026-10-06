import json
import sqlite3
from datetime import datetime, timezone

from .audit import GENESIS, audit_hash, canonical_json, make_entry, reconcile_ledger, verify_global, verify_item
from .domain import ConflictError, NotFoundError, DomainError


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, path):
        self.path = path

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, stable_key)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    seq INTEGER,
                    global_previous_hash TEXT,
                    global_hash TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_item ON audit_events(item_id, id);
                CREATE TABLE IF NOT EXISTS regulator_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    anchor TEXT NOT NULL,
                    issued_by TEXT,
                    note TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(period, seq)
                );
                CREATE TABLE IF NOT EXISTS ledger_quarantine (
                    item_id INTEGER PRIMARY KEY,
                    fork_start_seq INTEGER NOT NULL,
                    last_consistent_seq INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    status_before TEXT,
                    opened_at TEXT NOT NULL,
                    opened_by TEXT,
                    released_at TEXT,
                    released_by TEXT,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                """
            )
            self._migrate_global_ledger(conn)
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(seq)")
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 旧数据升级：按原顺序补齐总账摘要，既有摘要值不许改动，可重复执行
    # ------------------------------------------------------------------
    def _migrate_global_ledger(self, conn):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
        if "seq" not in columns:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ALTER TABLE audit_events ADD COLUMN seq INTEGER")
            conn.execute("ALTER TABLE audit_events ADD COLUMN global_previous_hash TEXT")
            conn.execute("ALTER TABLE audit_events ADD COLUMN global_hash TEXT")
            try:
                self._backfill_global_chain(conn)
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        elif conn.execute("SELECT COUNT(*) AS total FROM audit_events WHERE seq IS NULL").fetchone()["total"]:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._backfill_global_chain(conn)
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def _backfill_global_chain(self, conn):
        pending = conn.execute(
            "SELECT * FROM audit_events WHERE seq IS NULL ORDER BY id"
        ).fetchall()
        if not pending:
            return
        last_row = conn.execute(
            "SELECT seq, global_hash FROM audit_events WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = last_row["seq"] if last_row else 0
        previous = last_row["global_hash"] if last_row else GENESIS
        for row in pending:
            seq += 1
            entry = {
                "item_id": row["item_id"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "role": row["role"],
                "payload": json.loads(row["payload"]),
                "created_at": row["created_at"],
            }
            anchor = audit_hash(previous, entry)
            conn.execute(
                "UPDATE audit_events SET seq=?, global_previous_hash=?, global_hash=? WHERE id=?",
                (seq, previous, anchor, row["id"]),
            )
            previous = anchor

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _last_item_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else GENESIS

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        """同一事务内同时推进事件链与整库总账链；链位由写事务串行分配。"""
        created_at = now_iso()
        entry = make_entry(item_id, event_type, actor, role, payload, created_at)
        item_previous = self._last_item_hash(conn, item_id)
        item_hash = audit_hash(item_previous, entry)
        global_previous = conn.execute(
            "SELECT global_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        global_previous = global_previous["global_hash"] if global_previous else GENESIS
        next_seq_row = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM audit_events").fetchone()
        next_seq = next_seq_row["next_seq"]
        global_hash = audit_hash(global_previous, entry)
        savepoint = "sp_audit_%d" % next_seq
        conn.execute("SAVEPOINT %s" % savepoint)
        try:
            conn.execute(
                "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,"
                "created_at,seq,global_previous_hash,global_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    item_id,
                    event_type,
                    actor,
                    role,
                    canonical_json(payload),
                    item_previous,
                    item_hash,
                    created_at,
                    next_seq,
                    global_previous,
                    global_hash,
                ),
            )
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK TO SAVEPOINT %s" % savepoint)
            raise ConflictError("ledger_position_conflict", "总账链位已被占用，请重试")
        conn.execute("RELEASE SAVEPOINT %s" % savepoint)
        return {"seq": next_seq, "anchor": global_hash}

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        initial_status,
                        1,
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_item", "同一业务实体已经存在")
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            ledger = self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return self._row_to_item(row)
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute("SELECT * FROM items WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?)",
                    (item_id, source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
            )
            conn.execute("COMMIT")
            return {"id": source_id, "item_id": item_id, "source_type": source_type, "external_id": external_id, "payload": payload, "observed_at": observed_at}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_sources(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), item_id),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload)
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 查账：按接近事件逐条 + 整库连续总账
    # ------------------------------------------------------------------
    def _audit_rows_for_item(self, conn, item_id):
        rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["payload"] = json.loads(value["payload"])
            result.append(value)
        return result

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            return self._audit_rows_for_item(conn, item_id)
        finally:
            conn.close()

    def item_ledger(self, item_id):
        conn = self.connect()
        try:
            if conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone() is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            events = self._audit_rows_for_item(conn, item_id)
            return {"events": events, "chain": verify_item(events)}
        finally:
            conn.close()

    def _global_rows(self, conn):
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        normalized = []
        for row in rows:
            value = dict(row)
            value["payload"] = json.loads(value["payload"])
            normalized.append(value)
        return normalized

    def global_ledger(self):
        conn = self.connect()
        try:
            rows = self._global_rows(conn)
            chain = verify_global(rows)
            receipts = conn.execute(
                "SELECT period, seq, anchor, created_at FROM regulator_receipts ORDER BY seq"
            ).fetchall()
            return {
                "length": len(rows),
                "events": rows,
                "chain": chain,
                "receipts": [dict(row) for row in receipts],
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 监管回执与对账
    # ------------------------------------------------------------------
    def register_receipt(self, period, seq, anchor, actor, note=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            head = conn.execute("SELECT COALESCE(MAX(seq), 0) AS head FROM audit_events").fetchone()["head"]
            if seq < 1 or seq > head:
                raise DomainError("anchor_out_of_range", "回执锚点链位超出当前总账范围", 400)
            try:
                conn.execute(
                    "INSERT INTO regulator_receipts(period,seq,anchor,issued_by,note,created_at) VALUES(?,?,?,?,?,?)",
                    (period, seq, anchor, actor, note, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_receipt", "该季度此链位的回执已经登记")
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_receipts(self):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM regulator_receipts ORDER BY seq, id").fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def reconcile(self, anchors=None, enforce=True, actor=None):
        """重算整库总账并与监管回执锚值核对；分叉涉及事件隔离处置。"""
        conn = self.connect()
        try:
            rows = self._global_rows(conn)
            if anchors is None:
                receipt_rows = conn.execute(
                    "SELECT seq, anchor FROM regulator_receipts ORDER BY seq"
                ).fetchall()
                anchors = [{"seq": row["seq"], "anchor": row["anchor"]} for row in receipt_rows]
            report = reconcile_ledger(rows, anchors)
            quarantine = None
            if enforce and report["fork_start_seq"] is not None:
                conn.execute("BEGIN IMMEDIATE")
                rows = self._global_rows(conn)
                report = reconcile_ledger(rows, anchors)
                quarantine = self._enforce_fork(
                    conn,
                    report["fork_start_seq"],
                    report["last_consistent"]["seq"],
                    report["affected_item_ids"],
                    actor,
                )
                conn.execute("COMMIT")
            report["containment"] = quarantine
            return report
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _enforce_fork(self, conn, fork_start_seq, last_consistent_seq, affected_item_ids, actor):
        """分叉涉及的接近事件停止批准和下发；已批准未执行的退回重议。"""
        opened = []
        returned = []
        timestamp = now_iso()
        for item_id in affected_item_ids:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                continue
            status_before = row["status"]
            existing = conn.execute(
                "SELECT item_id FROM ledger_quarantine WHERE item_id=? AND released_at IS NULL",
                (item_id,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO ledger_quarantine(item_id,fork_start_seq,last_consistent_seq,reason,"
                    "status_before,opened_at,opened_by) VALUES(?,?,?,?,?,?,?)",
                    (
                        item_id,
                        fork_start_seq,
                        last_consistent_seq,
                        "ledger_fork",
                        status_before,
                        timestamp,
                        actor,
                    ),
                )
                opened.append(item_id)
            # 已批准未执行（coordinating）：退回 assessed 重议
            if status_before == "coordinating":
                payload = json.loads(row["payload"])
                payload["returned_for_review"] = {
                    "at": timestamp,
                    "reason": "ledger_fork",
                    "fork_start_seq": fork_start_seq,
                    "last_consistent_seq": last_consistent_seq,
                    "returned_by": actor,
                }
                version = int(row["version"]) + 1
                conn.execute(
                    "UPDATE items SET status='assessed', version=?, payload=?, updated_at=? WHERE id=?",
                    (version, canonical_json(payload), timestamp, item_id),
                )
                self.append_audit(
                    conn,
                    item_id,
                    "returned_for_review",
                    actor,
                    "regulator",
                    {
                        "status_before": status_before,
                        "fork_start_seq": fork_start_seq,
                        "last_consistent_seq": last_consistent_seq,
                    },
                )
                returned.append(item_id)
        return {
            "quarantined": opened,
            "returned_for_review": returned,
            "already_quarantined": [item_id for item_id in affected_item_ids if item_id not in opened],
        }

    def release_quarantine(self, item_id, actor, note=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM ledger_quarantine WHERE item_id=? AND released_at IS NULL",
                (item_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("not_quarantined", "该事件不在隔离中")
            timestamp = now_iso()
            conn.execute(
                "UPDATE ledger_quarantine SET released_at=?, released_by=? WHERE item_id=? AND released_at IS NULL",
                (timestamp, actor, item_id),
            )
            self.append_audit(
                conn,
                item_id,
                "quarantine_released",
                actor,
                "regulator",
                {"note": note, "fork_start_seq": row["fork_start_seq"]},
            )
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def is_quarantined(self, conn, item_id):
        row = conn.execute(
            "SELECT item_id FROM ledger_quarantine WHERE item_id=? AND released_at IS NULL",
            (item_id,),
        ).fetchone()
        return row is not None

    def is_quarantined_open(self, item_id):
        conn = self.connect()
        try:
            return self.is_quarantined(conn, item_id)
        finally:
            conn.close()

    def list_quarantined(self):
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT q.*, i.status AS current_status FROM ledger_quarantine q "
                "JOIN items i ON i.id = q.item_id WHERE q.released_at IS NULL ORDER BY q.item_id"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            quarantined = [
                row["item_id"]
                for row in conn.execute(
                    "SELECT item_id FROM ledger_quarantine WHERE released_at IS NULL"
                ).fetchall()
            ]
            return {"counts": counts, "items": self.list_items(), "quarantined": quarantined}
        finally:
            conn.close()
