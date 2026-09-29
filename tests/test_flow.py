import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, FinancialCrimeService  # noqa: E402


class FinancialCrimeFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = FinancialCrimeService(Path(self.tmp.name) / "test.db")
        self.entity = self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", ["远海"])
        self.customer = self.service.create_customer("analyst1", "analyst", self.entity["id"], "C-001", "CN", risk_score=0.2)

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_screening_case_freeze_and_report_flow(self):
        self.service.add_or_update_watchlist("sup1", "supervisor", "OFAC", "远海贸易", ["CN"])
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-001", self.customer["id"], 150000, "USD", "远海贸易", "CN"
        )
        self.assertEqual("escalated", ingested["transaction"]["status"])
        alert = ingested["alert"]
        triaged = self.service.triage_alert("inv1", "investigator", alert["id"], "escalate", "inv1", "CASE-001")
        case = triaged["case"]
        case = self.service.update_case("inv1", "investigator", case["id"], "已核实交易链", case["version"], "escalated")
        case = self.service.freeze_entity("sup1", "supervisor", self.entity["id"], "制裁命中", self.entity["version"], case["id"])
        self.assertEqual(1, case["frozen"])
        blocked = self.service.ingest_transaction("analyst1", "analyst", "T-002", self.customer["id"], 100, "USD", "普通供应商", "US")
        self.assertEqual("blocked", blocked["transaction"]["status"])
        current = self.service.get_case("sup1", "supervisor", triaged["case"]["id"])["case"]
        reported = self.service.file_report("sup1", "supervisor", current["id"], "STR-001", current["version"])
        self.assertEqual("report_filed", reported["status"])

    def test_entity_merge_updates_transactions_and_keeps_audit(self):
        target = self.service.create_entity("sup1", "supervisor", "organization", "远海集团", [])
        transaction = self.service.ingest_transaction("analyst1", "analyst", "T-010", self.customer["id"], 1000, "CNY", "普通客户", "CN")["transaction"]
        merged = self.service.merge_entities("sup1", "supervisor", self.entity["id"], target["id"], self.entity["version"], target["version"])
        self.assertEqual(target["id"], merged["source"]["merged_into"])
        self.assertIn("远海贸易", merged["target"]["aliases"])
        later = self.service.ingest_transaction("analyst1", "analyst", "T-011", self.customer["id"], 2000, "CNY", "普通客户", "CN")
        self.assertEqual(target["id"], later["resolved_entity_id"])
        with self.assertRaises(DomainError):
            self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", [])
        self.assertEqual(target["id"], later["transaction"]["entity_id"])

    def test_case_confidentiality_concurrency_and_freeze_permission(self):
        alert = self.service.ingest_transaction(
            "analyst1", "analyst", "T-020", self.customer["id"], 200000, "USD", "未知公司", "US"
        )["alert"]
        case = self.service.triage_alert("sup1", "supervisor", alert["id"], "escalate", "inv1", "CASE-020")["case"]
        with self.assertRaises(DomainError) as ctx:
            self.service.get_case("inv2", "investigator", case["id"])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx2:
            self.service.freeze_entity("analyst1", "analyst", self.entity["id"], "越权", self.entity["version"])
        self.assertEqual(403, ctx2.exception.status)
        updated = self.service.update_case("inv1", "investigator", case["id"], "第一条", case["version"])
        with self.assertRaises(DomainError) as ctx3:
            self.service.update_case("inv1", "investigator", case["id"], "旧版本", case["version"])
        self.assertEqual(409, ctx3.exception.status)
        self.assertEqual(updated["version"] + 1, self.service.update_case("inv1", "investigator", case["id"], "第二条", updated["version"])["version"])


class WatchlistSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        self.service = FinancialCrimeService(self.db_path)
        self.entity = self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", ["远海"])
        self.customer = self.service.create_customer("analyst1", "analyst", self.entity["id"], "C-100", "CN", risk_score=0.2)

    def tearDown(self):
        self.tmp.cleanup()

    def _match_case(self, txn_ref):
        result = self.service.ingest_transaction(
            "analyst1", "analyst", txn_ref, self.customer["id"], 150000, "USD", "远海贸易", "CN"
        )
        return result

    def test_publish_snapshot_and_archive_hit_details_on_ingest(self):
        snapshot = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC",
            [{"name": "远海贸易", "countries": ["CN"]}, {"name": "其他公司", "countries": ["CN"], "active": False}],
            "BATCH-001",
        )
        self.assertEqual(1, snapshot["version"])
        self.assertEqual(2, snapshot["entry_count"])
        ingested = self._match_case("T-100")
        transaction = ingested["transaction"]
        self.assertEqual(snapshot["id"], transaction["screening_snapshot_id"])
        self.assertEqual(1, transaction["screening_version"])
        self.assertEqual("远海贸易", json.loads(transaction["match_details"])["entry_name"])

        self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC", [{"name": "完全不同名单", "countries": ["CN"]}], "BATCH-002"
        )
        with sqlite3.connect(self.db_path) as conn:
            archived_id, entry_count = conn.execute(
                "SELECT screening_snapshot_id,(SELECT COUNT(*) FROM watchlist_snapshot_entries WHERE snapshot_id=?) "
                "FROM transactions WHERE id=?",
                (snapshot["id"], transaction["id"]),
            ).fetchone()
        self.assertEqual(snapshot["id"], archived_id)
        self.assertEqual(2, entry_count)

    def test_snapshot_rows_are_immutable(self):
        snapshot = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC", [{"name": "远海贸易", "countries": ["CN"]}]
        )
        with sqlite3.connect(self.db_path) as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE watchlist_snapshots SET entry_count=2 WHERE id=?", (snapshot["id"],))
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE watchlist_snapshot_entries SET name='改写' WHERE snapshot_id=?", (snapshot["id"],))
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM watchlist_snapshots WHERE id=?", (snapshot["id"],))

    def test_nightly_review_creates_revocable_todos_and_only_appends_case_records(self):
        self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC", [{"name": "旧名单公司", "countries": ["CN"]}], "B-OLD"
        )
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-200", self.customer["id"], 1000, "USD", "远海贸易", "CN"
        )
        transaction_id = ingested["transaction"]["id"]
        self.assertIsNone(ingested["transaction"]["match_details"])

        prior_alert = self.service.ingest_transaction(
            "analyst1", "analyst", "T-199", self.customer["id"], 150000, "USD", "远海贸易", "CN"
        )["alert"]
        case = self.service.triage_alert("inv1", "investigator", prior_alert["id"], "escalate", "inv1", "CASE-200")["case"]
        new_snapshot = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC", [{"name": "远海贸易", "countries": ["CN"]}], "B-NEW"
        )
        self._match_case("T-201")
        before = self.service.get_case("inv1", "investigator", case["id"])["case"]
        review = self.service.run_nightly_review("nightly", "supervisor", new_snapshot["id"])
        todo_id = review["created_todo_ids"][0]
        after = self.service.get_case("inv1", "investigator", case["id"])["case"]
        self.assertEqual(2, len(review["created_todo_ids"]))
        self.assertEqual([case["id"]], review["case_record_ids"])
        self.assertEqual(before["version"], after["version"])
        self.assertEqual(before["status"], after["status"])
        self.assertIn("夜间复核", self.service.get_case("inv1", "investigator", case["id"])["notes"][-1]["note"])

        with sqlite3.connect(self.db_path) as conn:
            unchanged = conn.execute(
                "SELECT screening_snapshot_id,match_details,status FROM transactions WHERE id=?", (transaction_id,)
            ).fetchone()
        self.assertIsNone(unchanged[0])
        self.assertIsNone(unchanged[1])

        removed = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC", [{"name": "另一家公司", "countries": ["CN"]}], "B-REMOVE"
        )
        second = self.service.run_nightly_review("nightly", "supervisor", removed["id"])
        todos = self.service.list_screening_todos("sup1", "supervisor")["todos"]
        todo = next(item for item in todos if item["id"] == todo_id)
        self.assertEqual("revoked", todo["status"])
        self.assertIn(todo_id, second["auto_revoked_todo_ids"])

        another = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC", [{"name": "远海贸易", "countries": ["CN"]}], "B-AGAIN"
        )
        third = self.service.run_nightly_review("nightly", "supervisor", another["id"])
        manual_id = third["created_todo_ids"][0]
        manual = self.service.revoke_screening_todo("sup1", "supervisor", manual_id, "人工复核确认误报")
        self.assertEqual("revoked", manual["status"])
        self.assertEqual("人工复核确认误报", manual["resolution_note"])
        with self.assertRaises(DomainError):
            self.service.revoke_screening_todo("sup1", "supervisor", manual_id, "重复撤销")

    def test_legacy_itemwise_rows_migrate_to_version_one_snapshot(self):
        with sqlite3.connect(self.db_path) as conn:
            now = "2026-01-01T00:00:00+00:00"
            conn.execute(
                "INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at) VALUES(?,?,?,?,1,1,?,?)",
                ("OFAC", "远海贸易", "远海贸易", '["CN"]', "legacy-sup", now),
            )
            conn.execute(
                "INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at) VALUES(?,?,?,?,1,0,?,?)",
                ("OFAC", "失效实体", "失效实体", "[]", "legacy-sup", now),
            )
            conn.commit()
        migrated_service = FinancialCrimeService(self.db_path)
        snapshots = migrated_service.list_watchlist_snapshots("sup1", "supervisor", "OFAC", True)["snapshots"]
        self.assertEqual(1, len(snapshots))
        self.assertEqual(1, snapshots[0]["version"])
        self.assertEqual("legacy_migration", snapshots[0]["source"])
        self.assertEqual(2, snapshots[0]["entry_count"])
        self.assertEqual({"远海贸易", "失效实体"}, {item["name"] for item in snapshots[0]["entries"]})
        result = migrated_service.ingest_transaction(
            "analyst1", "analyst", "T-300", self.customer["id"], 1000, "USD", "远海贸易", "CN"
        )
        self.assertEqual(snapshots[0]["id"], result["transaction"]["screening_snapshot_id"])

    def test_publish_and_ingest_serialize_without_half_published_batch(self):
        barrier = threading.Barrier(2)
        errors = []

        def publish():
            try:
                barrier.wait()
                self.service.publish_watchlist_snapshot(
                    "sup1", "supervisor", "OFAC", [{"name": "远海贸易", "countries": ["CN"]}], "CONCURRENT"
                )
            except Exception as exc:  # pragma: no cover - failure path reported to main thread
                errors.append(exc)

        def ingest():
            try:
                barrier.wait()
                self.service.ingest_transaction(
                    "analyst1", "analyst", "T-400", self.customer["id"], 1000, "USD", "远海贸易", "CN"
                )
            except Exception as exc:  # pragma: no cover - failure path reported to main thread
                errors.append(exc)

        threads = [threading.Thread(target=publish), threading.Thread(target=ingest)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        snapshots = self.service.list_watchlist_snapshots("sup1", "supervisor")["snapshots"]
        self.assertEqual(1, len(snapshots))
        with sqlite3.connect(self.db_path) as conn:
            entry_count = conn.execute("SELECT COUNT(*) FROM watchlist_snapshot_entries WHERE snapshot_id=?", (snapshots[0]["id"],)).fetchone()[0]
        self.assertEqual(1, entry_count)


if __name__ == "__main__":
    unittest.main()
