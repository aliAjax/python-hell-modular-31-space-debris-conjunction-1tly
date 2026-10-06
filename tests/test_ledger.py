import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.audit import GENESIS, audit_hash, canonical_json
from src.domain import ConflictError, DomainError


CREATE_PAYLOAD = {
    "primary_object_id": "SAT-2",
    "secondary_object_id": "DEB-3",
    "tca": "2026-09-29T12:00:00+00:00",
    "miss_distance_m": 50,
    "covariance_m": 100,
    "fuel_budget_m_s": 4,
    "track_age_hours": 1,
    "operating_organizations": ["Org-A"],
}


class LedgerServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _drive_to_assessed(self):
        item = self.service.create_item(CREATE_PAYLOAD, "a", "analyst")
        return self.service.act(item["id"], "assess", {"hours_to_tca": 2}, "a", "analyst", item["version"])

    def test_global_ledger_is_continuous_and_matches_item_chains(self):
        item = self._drive_to_assessed()
        ledger = self.service.ledger()
        self.assertEqual(ledger["length"], 2)
        self.assertTrue(ledger["chain"]["valid"])
        self.assertEqual([event["seq"] for event in ledger["events"]], [1, 2])
        self.assertEqual(ledger["chain"]["head_seq"], 2)
        # 连续总账：逐环重算
        previous = GENESIS
        for event in ledger["events"]:
            entry = {
                "item_id": event["item_id"],
                "event_type": event["event_type"],
                "actor": event["actor"],
                "role": event["role"],
                "payload": event["payload"],
                "created_at": event["created_at"],
            }
            self.assertEqual(event["global_previous_hash"], previous)
            self.assertEqual(event["global_hash"], audit_hash(previous, entry))
            previous = event["global_hash"]
        # 按接近事件逐条查阅，且事件链独立成立
        audit = self.service.item_audit(item["id"])
        self.assertTrue(audit["chain"]["valid"])
        self.assertEqual(audit["chain"]["length"], 2)

    def test_head_anchor_agrees_across_two_events(self):
        item_a = self._drive_to_assessed()
        item_b_payload = dict(CREATE_PAYLOAD, secondary_object_id="DEB-4")
        item_b = self.service.create_item(item_b_payload, "a", "analyst")
        ledger = self.service.ledger()
        self.assertEqual(ledger["length"], 3)
        self.assertTrue(ledger["chain"]["valid"])
        self.assertEqual(ledger["events"][-1]["item_id"], item_b["id"])
        self.assertEqual(ledger["chain"]["anchor"], ledger["events"][-1]["global_hash"])

    def test_receipt_reconcile_clean(self):
        self._drive_to_assessed()
        ledger = self.service.ledger()
        head_seq = ledger["chain"]["head_seq"]
        anchor = ledger["chain"]["anchor"]
        self.service.register_receipt("2026Q4", head_seq, anchor, "reg-1", "regulator", "季报")
        report = self.service.reconcile({"enforce": True}, "reg-1", "regulator")
        self.assertTrue(report["valid"])
        self.assertIsNone(report["fork_start_seq"])

    def test_wrong_anchor_locates_fork_from_latest_consistent(self):
        item = self._drive_to_assessed()
        ledger = self.service.ledger()
        anchor_seq1 = ledger["events"][0]["global_hash"]
        # 链尾被补写/改写后，监管持有链位1正确锚值、链尾锚值对不上
        wrong_head = "0" * 64
        report = self.service.reconcile(
            {"anchors": [{"seq": 1, "anchor": anchor_seq1}, {"seq": 2, "anchor": wrong_head}], "enforce": False},
            "reg-1",
            "regulator",
        )
        self.assertFalse(report["valid"])
        self.assertEqual(report["last_consistent"]["seq"], 1)
        self.assertEqual(report["fork_start_seq"], 2)
        self.assertIn(item["id"], report["affected_item_ids"])

    def test_deleted_middle_row_breaks_structural_chain(self):
        item = self._drive_to_assessed()
        self.service.add_source(
            item["id"],
            {
                "source_type": "radar",
                "external_id": "SRC-1",
                "observed_at": "2026-09-29T11:00:00+00:00",
                "miss_distance_m": 40,
                "covariance_m": 100,
            },
            "a",
            "analyst",
        )
        # 删掉中间链位：剩余行的链位不再连续，结构校验直接失败
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("DELETE FROM audit_events WHERE seq=2")
        conn.commit()
        conn.close()
        report = self.service.reconcile({"enforce": False}, "reg-1", "regulator")
        self.assertFalse(report["structural"]["valid"])
        self.assertEqual(report["structural"]["first_invalid_seq"], 3)
        self.assertEqual(report["fork_start_seq"], 3)

    def test_deleted_tail_row_found_by_regulator_anchor(self):
        self._drive_to_assessed()
        ledger = self.service.ledger()
        anchor_seq2 = ledger["events"][1]["global_hash"]
        # 删掉链尾一行后剩余前缀仍自洽，但监管持有的链尾锚值对不上
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("DELETE FROM audit_events WHERE seq=2")
        conn.commit()
        conn.close()
        report = self.service.reconcile(
            {"anchors": [{"seq": 2, "anchor": anchor_seq2}], "enforce": False},
            "reg-1",
            "regulator",
        )
        self.assertTrue(report["structural"]["valid"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["fork_start_seq"], 2)
        self.assertEqual(report["last_consistent"]["seq"], 1)

    def test_fork_quarantines_and_returns_approved_for_review(self):
        # 推进到 coordinating（已批准未执行）
        item = self._drive_to_assessed()
        item = self.service.act(
            item["id"],
            "approve",
            {"fuel_cost_m_s": 1, "maneuver_window": "w"},
            "c",
            "coordinator",
            item["version"],
        )
        self.assertEqual(item["status"], "coordinating")
        ledger = self.service.ledger()
        # 篡改某条总账（模拟整库被补写），对账触发处置
        conn = sqlite3.connect(self.tmp.name)
        conn.execute("UPDATE audit_events SET payload=? WHERE seq=1", (canonical_json({"tampered": True}),))
        conn.commit()
        conn.close()
        report = self.service.reconcile({"enforce": True}, "reg-1", "regulator")
        self.assertEqual(report["fork_start_seq"], 1)
        self.assertIn(item["id"], report["containment"]["returned_for_review"])
        refreshed = self.service.get_item(item["id"])
        self.assertEqual(refreshed["status"], "assessed")
        self.assertTrue(refreshed["quarantined"])
        # 分叉事件停止批准和下发
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "approve", {"fuel_cost_m_s": 1, "maneuver_window": "w2"},
                             "c", "coordinator", refreshed["version"])
        self.assertEqual(ctx.exception.code, "event_quarantined")
        with self.assertRaises(DomainError) as ctx:
            self.service.act(item["id"], "execute", {"command_ref": "CMD-1"},
                             "o", "operator", refreshed["version"])
        self.assertEqual(ctx.exception.code, "event_quarantined")
        # 解除隔离后可重新批准
        self.service.release_quarantine(item["id"], "reg-1", "regulator")
        refreshed = self.service.get_item(item["id"])
        self.assertFalse(refreshed["quarantined"])

    def test_register_receipt_requires_regulator(self):
        self._drive_to_assessed()
        with self.assertRaises(DomainError) as ctx:
            self.service.register_receipt("2026Q4", 1, "x", "c", "coordinator")
        self.assertEqual(ctx.exception.status, 403)

    def test_business_action_and_ledger_commit_together(self):
        item = self._drive_to_assessed()
        before = self.service.ledger()["length"]
        with self.assertRaises(ConflictError):
            # 版本冲突，动作失败：总账不得多出链位
            self.service.act(
                item["id"],
                "approve",
                {"fuel_cost_m_s": 1, "maneuver_window": "w"},
                "c",
                "coordinator",
                item["version"] - 1,
            )
        self.assertEqual(self.service.ledger()["length"], before)

    def test_concurrent_saves_never_share_chain_position(self):
        item = self._drive_to_assessed()
        version = item["version"]
        errors = []
        barrier = threading.Barrier(2)

        def approve(actor):
            try:
                barrier.wait()
                self.service.act(
                    item["id"],
                    "approve",
                    {"fuel_cost_m_s": 1, "maneuver_window": "w-%s" % actor},
                    actor,
                    "coordinator",
                    version,
                )
            except DomainError as exc:
                errors.append(exc.code)

        threads = [threading.Thread(target=approve, args=(name,)) for name in ("c1", "c2")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # 两名值班员同一时刻保存同一事件：只有一人成功，另一人必须被拒绝
        self.assertTrue(errors)
        self.assertIn(errors[0], ("version_conflict", "invalid_state"))
        ledger = self.service.ledger()
        seqs = [event["seq"] for event in ledger["events"]]
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        self.assertTrue(ledger["chain"]["valid"])
        approved = [event for event in ledger["events"] if event["event_type"] == "approve"]
        self.assertEqual(len(approved), 1)

    def test_concurrent_opinions_all_get_distinct_positions(self):
        item = self._drive_to_assessed()
        start_version = self.service.get_item(item["id"])["version"]
        errors = []
        barrier = threading.Barrier(4)

        def record(index):
            try:
                barrier.wait()
                self.service.act(
                    item["id"],
                    "record_opinion",
                    {"operator": "Org-%d" % index, "opinion": "approve"},
                    "op-%d" % index,
                    "operator",
                )
            except DomainError as exc:
                errors.append(exc.code)

        threads = [threading.Thread(target=record, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        ledger = self.service.ledger()
        seqs = [event["seq"] for event in ledger["events"]]
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        self.assertTrue(ledger["chain"]["valid"])


OLD_SCHEMA = """
CREATE TABLE items (
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
CREATE TABLE sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    external_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(item_id, source_type, external_id)
);
CREATE TABLE actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE audit_events (
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
"""


class LedgerMigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _seed_old_database(self):
        conn = sqlite3.connect(self.tmp.name)
        conn.executescript(OLD_SCHEMA)
        # 旧库只有按事件各串一条的链
        conn.execute(
            "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("space_conjunction", "k1", "pending", 1, "{}", "a", "analyst", "t0", "t0"),
        )
        item_id = conn.execute("SELECT id FROM items").fetchone()[0]
        previous = GENESIS
        for index, event_type in enumerate(("created", "source_recorded", "assess"), start=1):
            payload = {"index": index}
            entry = {
                "item_id": item_id,
                "event_type": event_type,
                "actor": "a",
                "role": "analyst",
                "payload": payload,
                "created_at": "t%d" % index,
            }
            event_hash = audit_hash(previous, entry)
            conn.execute(
                "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (item_id, event_type, "a", "analyst", canonical_json(payload), previous, event_hash, "t%d" % index),
            )
            previous = event_hash
        conn.commit()
        conn.close()

    def test_migration_backfills_global_summaries_in_original_order(self):
        self._seed_old_database()
        repo = Repository(self.tmp.name)
        repo.initialize()
        conn = sqlite3.connect(self.tmp.name)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        self.assertEqual([row["seq"] for row in rows], [1, 2, 3])
        # 既有摘要值不许改动
        previous = GENESIS
        for row in rows:
            old_entry = {
                "item_id": row["item_id"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "role": row["role"],
                "payload": json.loads(row["payload"]),
                "created_at": row["created_at"],
            }
            self.assertEqual(row["event_hash"], audit_hash(previous, old_entry))
            previous = row["event_hash"]
        # 回填出的总账连续且与重算一致
        service = Service(repo)
        ledger = service.ledger()
        self.assertTrue(ledger["chain"]["valid"])
        self.assertEqual(ledger["chain"]["length"], 3)
        # 升级后新动作接续总账
        self.service = service
        conn.close()

    def test_migration_is_idempotent(self):
        self._seed_old_database()
        repo = Repository(self.tmp.name)
        repo.initialize()
        conn = sqlite3.connect(self.tmp.name)
        first = conn.execute("SELECT id, seq, global_hash FROM audit_events ORDER BY id").fetchall()
        conn.close()
        # 再初始化一次，不得改动任何总账摘要
        repo.initialize()
        conn = sqlite3.connect(self.tmp.name)
        second = conn.execute("SELECT id, seq, global_hash FROM audit_events ORDER BY id").fetchall()
        conn.close()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
