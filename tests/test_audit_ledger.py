import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit import canonical_json
from src.domain import DomainError
from src.repository import Repository
from src.service import Service


def _payload(i):
    return {
        "primary_object_id": "SAT-%d" % i,
        "secondary_object_id": "DEB-%d" % i,
        "tca": "2026-10-0%dT12:00:00+00:00" % (i % 9 + 1),
        "miss_distance_m": 100 + i,
        "covariance_m": 100,
        "fuel_budget_m_s": 10,
        "track_age_hours": 1,
        "operating_organizations": ["Org-A"],
    }


class AuditLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _tamper(self, sql, params=()):
        conn = self.repo.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(sql, params)
            conn.execute("COMMIT")
        finally:
            conn.close()

    def test_ledger_advances_with_business_actions(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        self.service.add_source(
            item["id"],
            {"source_type": "radar", "external_id": "EXT-1", "observed_at": "2026-10-01T00:00:00+00:00", "miss_distance_m": 100, "covariance_m": 100},
            "a", "analyst",
        )
        ledger = self.service.ledger()
        self.assertEqual([e["event_type"] for e in ledger], ["created", "assess", "source_recorded"])
        self.assertEqual([e["seq"] for e in ledger], [1, 2, 3])
        # per-item chain still independently readable (逐条查阅)
        audit = self.repo.audit_trail(item["id"])
        self.assertEqual([e["event_type"] for e in audit], ["created", "assess", "source_recorded"])

    def test_receipt_anchor_reconciles(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        receipt = self.service.receipt()
        self.assertEqual(receipt["seq"], 2)
        res = self.service.reconcile(receipt["hash"], receipt["seq"])
        self.assertTrue(res["consistent"])
        self.assertIsNone(res["fork_seq"])
        res2 = self.service.reconcile()
        self.assertTrue(res2["consistent"])

    def test_tamper_modify_detected_at_fork(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        self.service.act(item["id"], "record_opinion", {"operator": "Org-A", "opinion": "approve"}, "o", "operator", item["version"])
        self._tamper("UPDATE ledger_entries SET payload=? WHERE seq=2", (canonical_json({"tampered": True}),))
        res = self.service.reconcile()
        self.assertFalse(res["consistent"])
        self.assertEqual(res["fork_seq"], 2)
        self.assertIn(item["id"], res["affected_items"])

    def test_tamper_delete_detected_at_fork(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        self.service.act(item["id"], "record_opinion", {"operator": "Org-A", "opinion": "approve"}, "o", "operator", item["version"])
        self._tamper("DELETE FROM ledger_entries WHERE seq=2")
        res = self.service.reconcile()
        self.assertFalse(res["consistent"])
        self.assertEqual(res["fork_seq"], 2)

    def test_backfill_preserves_order_and_existing_hashes(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        before = [(e["id"], e["event_hash"]) for e in self.repo.audit_trail(item["id"])]
        # simulate an old deployment: ledger empty, audit events present
        self._tamper("DELETE FROM ledger_entries")
        self.repo.initialize()  # upgrade -> backfill
        after = [(e["id"], e["event_hash"]) for e in self.repo.audit_trail(item["id"])]
        self.assertEqual(before, after, "existing audit digests must not change")
        ledger = self.service.ledger()
        self.assertEqual([e["seq"] for e in ledger], [1, 2])
        self.assertEqual([e["event_type"] for e in ledger], ["created", "assess"])
        self.assertTrue(self.service.reconcile()["consistent"])

    def test_fork_freezes_approve_and_execute_and_reverts_approved(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        item = self.service.act(item["id"], "approve", {"fuel_cost_m_s": 1, "maneuver_window": "w"}, "c", "coordinator", item["version"])
        self.assertEqual(item["status"], "coordinating")
        self._tamper("UPDATE ledger_entries SET payload=? WHERE seq=1", (canonical_json({"tampered": True}),))
        res = self.service.reconcile()
        self.assertFalse(res["consistent"])
        self.assertIn(item["id"], res["affected_items"])
        self.assertIn(item["id"], res["reverted_items"])
        reloaded = self.service.get_item(item["id"])
        self.assertEqual(reloaded["status"], "assessed")  # 退回重议
        self.assertEqual(reloaded["held"], 1)
        cases = [
            ("approve", "coordinator", {"fuel_cost_m_s": 1, "maneuver_window": "w"}),
            ("execute", "operator", {"command_ref": "CMD"}),
        ]
        for action, role, extra in cases:
            with self.assertRaises(DomainError) as ctx:
                self.service.act(item["id"], action, extra, "c", role, reloaded["version"])
            self.assertEqual(ctx.exception.code, "item_held")

    def test_repeated_reconcile_does_not_duplicate_holds(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        self._tamper("UPDATE ledger_entries SET payload=? WHERE seq=1", (canonical_json({"tampered": True}),))
        self.service.reconcile()
        ledger_len_after_first = len(self.service.ledger())
        self.service.reconcile()
        ledger_len_after_second = len(self.service.ledger())
        self.assertEqual(ledger_len_after_first, ledger_len_after_second)

    def test_concurrent_saves_no_duplicate_chain_position(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        errors = []

        def save(actor):
            try:
                self.service.act(item["id"], "assess", {"hours_to_tca": 12}, actor, "analyst")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        t1 = threading.Thread(target=save, args=("officer-1",))
        t2 = threading.Thread(target=save, args=("officer-2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertFalse(errors)
        seqs = [e["seq"] for e in self.service.ledger()]
        self.assertEqual(len(seqs), len(set(seqs)), "duplicate chain position: %s" % seqs)
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_stale_anchor_prefix_intact(self):
        item = self.service.create_item(_payload(1), "a", "analyst")
        item = self.service.act(item["id"], "assess", {"hours_to_tca": 10}, "a", "analyst", item["version"])
        old_receipt = self.service.receipt()
        item = self.service.act(item["id"], "record_opinion", {"operator": "Org-A", "opinion": "approve"}, "o", "operator", item["version"])
        res = self.service.reconcile(old_receipt["hash"], old_receipt["seq"])
        self.assertTrue(res["consistent"])
        self.assertTrue(res["anchor_matches"])
        # tamper inside the receipted prefix -> anchor no longer matches
        self._tamper("UPDATE ledger_entries SET payload=? WHERE seq=1", (canonical_json({"x": 1}),))
        res2 = self.service.reconcile(old_receipt["hash"], old_receipt["seq"])
        self.assertFalse(res2["consistent"])
        self.assertFalse(res2["anchor_matches"])
        self.assertEqual(res2["fork_seq"], 1)


if __name__ == "__main__":
    unittest.main()
