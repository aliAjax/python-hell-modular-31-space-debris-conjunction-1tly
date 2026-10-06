import json
import sqlite3
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError


def now_iso():
    return datetime.now(timezone.utc).isoformat()


GENESIS = "GENESIS"


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
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seq INTEGER NOT NULL UNIQUE,
                    audit_event_id INTEGER UNIQUE,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column(conn, "items", "held", "INTEGER NOT NULL DEFAULT 0")
            self.backfill_ledger(conn)
        finally:
            conn.close()

    def _ensure_column(self, conn, table, column, definition):
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()]
        if column not in cols:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, definition))

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else GENESIS

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        """Append to the per-item chain. Returns (audit_event_id, created_at)."""
        previous = self._last_hash(conn, item_id)
        created_at = now_iso()
        event = {
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": created_at,
        }
        event_hash = audit_hash(previous, event)
        cur = conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (item_id, event_type, actor, role, canonical_json(payload), previous, event_hash, created_at),
        )
        return cur.lastrowid, created_at

    def _last_ledger_hash(self, conn):
        row = conn.execute("SELECT entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1").fetchone()
        return row["entry_hash"] if row else GENESIS

    def _next_seq(self, conn):
        row = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM ledger_entries").fetchone()
        return row["next_seq"]

    def append_ledger(self, conn, audit_event_id, item_id, event_type, actor, role, payload, created_at):
        """Append to the global ledger. Must run inside BEGIN IMMEDIATE so the
        seq assignment is serialized across concurrent writers."""
        seq = self._next_seq(conn)
        previous = self._last_ledger_hash(conn)
        event = {
            "seq": seq,
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": created_at,
        }
        entry_hash = audit_hash(previous, event)
        conn.execute(
            "INSERT INTO ledger_entries(seq,audit_event_id,item_id,event_type,actor,role,payload,previous_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (seq, audit_event_id, item_id, event_type, actor, role, canonical_json(payload), previous, entry_hash, created_at),
        )
        return seq

    def backfill_ledger(self, conn):
        """Upgrade path: replay pre-existing audit_events into the global ledger
        in original (audit id) order.

        Existing ledger hashes are never recomputed or rewritten; only audit
        events missing from the ledger are appended, ordered by their original
        audit id. New-code deployments maintain the ledger themselves, so this
        is a no-op once the ledger has any rows.
        """
        has_ledger = conn.execute("SELECT 1 FROM ledger_entries LIMIT 1").fetchone()
        if has_ledger is not None:
            return
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        for row in rows:
            payload = json.loads(row["payload"])
            self.append_ledger(conn, row["id"], row["item_id"], row["event_type"], row["actor"], row["role"], payload, row["created_at"])

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
            audit_id, created_at = self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            self.append_ledger(conn, audit_id, item_id, "created", actor, role, {"stable_key": stable_key}, created_at)
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
            audit_id, created_at = self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
            )
            self.append_ledger(
                conn,
                audit_id,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
                created_at,
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
            audit_id, created_at = self.append_audit(conn, item_id, action, actor, role, event_payload)
            self.append_ledger(conn, audit_id, item_id, action, actor, role, event_payload, created_at)
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

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def list_ledger(self):
        """The global, continuous general ledger (整库连续的总账)."""
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM ledger_entries ORDER BY seq").fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def receipt(self):
        """The current ledger head: the anchor the regulator takes on receipt."""
        conn = self.connect()
        try:
            row = conn.execute("SELECT seq, entry_hash, created_at FROM ledger_entries ORDER BY seq DESC LIMIT 1").fetchone()
            if row is None:
                return {"seq": 0, "hash": GENESIS, "issued_at": None}
            return {"seq": row["seq"], "hash": row["entry_hash"], "issued_at": row["created_at"]}
        finally:
            conn.close()

    def reconcile(self, anchor=None, anchor_seq=None, apply_holds=True):
        """Replay the global ledger from genesis and reconcile against the
        regulator's receipt anchor.

        Walks the chain in order, recomputing every hash. The first position
        where the recomputed hash, the previous link, or the sequence number
        no longer matches is the fork (分叉) located from the last consistent
        point. If the receipt anchor cannot be reproduced anywhere in the
        recomputed chain, the receipted prefix has been tampered with.

        When apply_holds is true, fork-involved items (those appearing in
        ledger entries at or after the fork) are frozen: approval and dispatch
        are stopped, and approved-but-not-executed items (status coordinating)
        are returned to re-discussion (assessed).
        """
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT * FROM ledger_entries ORDER BY seq").fetchall()

            recomputed = GENESIS
            expected_seq = 1
            fork_seq = None
            recomputed_at_seq = {}
            head_seq = 0
            stored_head_hash = GENESIS
            for row in rows:
                head_seq = row["seq"]
                stored_head_hash = row["entry_hash"]
                if fork_seq is not None:
                    continue
                if row["seq"] != expected_seq:
                    fork_seq = expected_seq
                    continue
                event = {
                    "seq": row["seq"],
                    "item_id": row["item_id"],
                    "event_type": row["event_type"],
                    "actor": row["actor"],
                    "role": row["role"],
                    "payload": json.loads(row["payload"]),
                    "created_at": row["created_at"],
                }
                expected_hash = audit_hash(recomputed, event)
                if row["previous_hash"] != recomputed or row["entry_hash"] != expected_hash:
                    fork_seq = row["seq"]
                    continue
                recomputed = expected_hash
                recomputed_at_seq[row["seq"]] = expected_hash
                expected_seq += 1

            anchor_matches = None
            if anchor is not None:
                if head_seq == 0:
                    anchor_matches = anchor == GENESIS
                elif anchor_seq is not None:
                    anchor_matches = recomputed_at_seq.get(anchor_seq) == anchor
                else:
                    anchor_matches = anchor in recomputed_at_seq.values()

            consistent = fork_seq is None and (anchor is None or anchor_matches)

            affected_items = []
            reverted_items = []
            if not consistent and fork_seq is not None and apply_holds:
                affected_items = self._freeze_region(conn, fork_seq)
                reverted_items = self._revert_approved(conn, affected_items)
                head_row = conn.execute("SELECT seq, entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1").fetchone()
                if head_row is not None:
                    head_seq = head_row["seq"]
                    stored_head_hash = head_row["entry_hash"]

            conn.execute("COMMIT")
            return {
                "consistent": consistent,
                "fork_seq": fork_seq,
                "anchor": anchor,
                "anchor_seq": anchor_seq,
                "anchor_matches": anchor_matches,
                "head_seq": head_seq,
                "head_hash": stored_head_hash,
                "recomputed_head_hash": recomputed,
                "affected_items": affected_items,
                "held_items": affected_items,
                "reverted_items": reverted_items,
            }
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _freeze_region(self, conn, fork_seq):
        """Freeze every item appearing in ledger entries at or after the fork.

        Idempotent: items already held are not frozen twice, so repeated
        reconciles do not duplicate fork_hold events.
        """
        rows = conn.execute(
            "SELECT id, held FROM items WHERE id IN "
            "(SELECT DISTINCT item_id FROM ledger_entries WHERE seq >= ? AND item_id IS NOT NULL) ORDER BY id",
            (fork_seq,),
        ).fetchall()
        affected = []
        for row in rows:
            item_id = row["id"]
            affected.append(item_id)
            if row["held"]:
                continue
            conn.execute("UPDATE items SET held=1 WHERE id=?", (item_id,))
            audit_id, created_at = self.append_audit(
                conn,
                item_id,
                "fork_hold",
                "system",
                "regulator",
                {"reason": "fork_detected", "fork_seq": fork_seq},
            )
            self.append_ledger(
                conn,
                audit_id,
                item_id,
                "fork_hold",
                "system",
                "regulator",
                {"reason": "fork_detected", "fork_seq": fork_seq},
                created_at,
            )
        return affected

    def _revert_approved(self, conn, item_ids):
        """Return approved-but-not-executed items (coordinating) to re-discussion."""
        reverted = []
        for item_id in item_ids:
            row = conn.execute("SELECT status FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None or row["status"] != "coordinating":
                continue
            now = now_iso()
            audit_id, created_at = self.append_audit(
                conn,
                item_id,
                "returned_for_review",
                "system",
                "regulator",
                {"reason": "fork_detected", "from_status": "coordinating", "to_status": "assessed"},
            )
            self.append_ledger(
                conn,
                audit_id,
                item_id,
                "returned_for_review",
                "system",
                "regulator",
                {"reason": "fork_detected", "from_status": "coordinating", "to_status": "assessed"},
                created_at,
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, "returned_for_review", "system", "regulator", canonical_json({"reason": "fork_detected"}), created_at),
            )
            conn.execute(
                "UPDATE items SET status='assessed', version=version+1, updated_at=? WHERE id=?",
                (now, item_id),
            )
            reverted.append(item_id)
        return reverted

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()
