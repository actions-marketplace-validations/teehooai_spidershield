"""Tests for the local security dataset module."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from teeshield.cli import main
from teeshield.dataset.collector import (
    get_prs,
    record_hardener_fix,
    record_pr,
    record_pr_tool_change,
    record_rewrite,
    record_scan,
)
from teeshield.dataset.db import get_connection, get_stats, init_db


class TestDatabase:
    def test_init_creates_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        result = init_db(db_path)
        assert result == db_path
        assert db_path.exists()

    def test_init_idempotent(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        init_db(db_path)  # Should not raise
        assert db_path.exists()

    def test_schema_version(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        with get_connection(db_path) as conn:
            ver = conn.execute(
                "SELECT version FROM schema_version"
            ).fetchone()[0]
            assert ver == 2

    def test_get_stats_no_db(self, tmp_path: Path) -> None:
        stats = get_stats(tmp_path / "nonexistent.db")
        assert stats["db_exists"] is False
        assert stats["total_scans"] == 0

    def test_get_stats_empty_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        stats = get_stats(db_path)
        assert stats["db_exists"] is True
        assert stats["total_scans"] == 0
        assert stats["total_issues"] == 0


class TestCollector:
    def _make_report(self):
        """Create a minimal ScanReport for testing."""
        from teeshield.models import Rating, ScanReport, SecurityIssue

        return ScanReport(
            target="/tmp/test-server",
            tool_count=3,
            security_score=7.5,
            description_score=6.0,
            architecture_score=5.0,
            overall_score=6.3,
            rating=Rating.B,
            license="MIT",
            license_ok=True,
            has_tests=True,
            has_error_handling=False,
            security_issues=[
                SecurityIssue(
                    severity="high",
                    category="sql_injection",
                    file="server.py",
                    line=42,
                    description="f-string in SQL execute",
                    fix_suggestion="Use parameterized queries",
                ),
            ],
        )

    def test_record_scan(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(report, db_path=db_path)
        assert scan_id is not None
        assert scan_id > 0

        stats = get_stats(db_path)
        assert stats["total_scans"] == 1
        assert stats["total_issues"] == 1

    def test_record_scan_preserves_data(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(report, db_path=db_path)

        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            assert row["target"] == "/tmp/test-server"
            assert row["security_score"] == 7.5
            assert row["rating"] == "B"

            issues = conn.execute(
                "SELECT * FROM security_issues WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
            assert len(issues) == 1
            assert issues[0]["category"] == "sql_injection"

    def test_record_rewrite(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        rid = record_rewrite(
            target="/tmp/test",
            tool_name="read_file",
            original="Read a file",
            rewritten="Read the contents of a file at the specified path.",
            original_score=3.0,
            rewritten_score=8.5,
            engine="template",
            passed=True,
            db_path=db_path,
        )
        assert rid is not None

        stats = get_stats(db_path)
        assert stats["total_descriptions"] == 1

    def test_record_hardener_fix(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        fid = record_hardener_fix(
            target="/tmp/test",
            category="sql_injection",
            file="server.py",
            suggestion="Use parameterized queries",
            code_fix="cursor.execute('SELECT ?', (val,))",
            confidence=0.85,
            engine="llm",
            db_path=db_path,
        )
        assert fid is not None

        stats = get_stats(db_path)
        assert stats["total_fixes"] == 1

    def test_record_scan_never_raises(self, tmp_path: Path) -> None:
        """Collector should silently handle errors."""
        # Pass a garbage object -- should return None, not raise
        result = record_scan("not a report", db_path=tmp_path / "test.db")
        assert result is None

    def test_multiple_scans_accumulate(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        record_scan(report, db_path=db_path)
        record_scan(report, db_path=db_path)
        record_scan(report, db_path=db_path)

        stats = get_stats(db_path)
        assert stats["total_scans"] == 3
        assert stats["total_issues"] == 3
        assert stats["unique_targets"] == 1


class TestDatasetCLI:
    def test_dataset_stats_empty(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH",
            tmp_path / "nonexistent.db",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "stats"])
        assert result.exit_code == 0
        assert "No dataset" in result.output

    def test_dataset_stats_with_data(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        # Seed some data
        from teeshield.models import Rating, ScanReport

        report = ScanReport(
            target="/tmp/test",
            tool_count=2,
            security_score=8.0,
            description_score=7.0,
            architecture_score=6.0,
            overall_score=7.2,
            rating=Rating.B,
        )
        record_scan(report, db_path=db_path)

        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "stats"])
        assert result.exit_code == 0
        assert "Scans: 1" in result.output

    def test_dataset_export_json(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        from teeshield.models import Rating, ScanReport

        report = ScanReport(
            target="/tmp/test",
            tool_count=1,
            security_score=9.0,
            description_score=8.0,
            architecture_score=7.0,
            overall_score=8.2,
            rating=Rating.A,
        )
        record_scan(report, db_path=db_path)

        out = tmp_path / "export.json"
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "export", str(out)])
        assert result.exit_code == 0
        assert out.exists()

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == 2
        assert len(data["scans"]) == 1
        assert "pull_requests" in data

    def test_dataset_export_no_data(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH",
            tmp_path / "nonexistent.db",
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["dataset", "export", str(tmp_path / "out.json")],
        )
        assert result.exit_code != 0

    def test_dataset_reset(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        assert db_path.exists()

        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "reset"], input="y\n")
        assert result.exit_code == 0
        assert not db_path.exists()


class TestPRTracking:
    def test_record_pr(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        pr_id = record_pr(
            repo="org/repo",
            pr_number=42,
            title="Improve tool descriptions",
            status="open",
            strategy="hand-crafted",
            tools_changed=5,
            db_path=db_path,
        )
        assert pr_id is not None

    def test_record_pr_upsert(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        record_pr(
            repo="org/repo", pr_number=1, title="v1",
            status="open", db_path=db_path,
        )
        record_pr(
            repo="org/repo", pr_number=1, title="v2",
            status="merged", db_path=db_path,
        )
        prs = get_prs(db_path=db_path)
        assert len(prs) == 1
        assert prs[0]["status"] == "merged"
        assert prs[0]["title"] == "v2"

    def test_get_prs_filter(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        record_pr(
            repo="a/b", pr_number=1, title="Open PR",
            status="open", db_path=db_path,
        )
        record_pr(
            repo="c/d", pr_number=2, title="Merged PR",
            status="merged", db_path=db_path,
        )
        open_prs = get_prs(status="open", db_path=db_path)
        assert len(open_prs) == 1
        assert open_prs[0]["repo"] == "a/b"

    def test_record_pr_tool_change(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        pr_id = record_pr(
            repo="org/repo", pr_number=10, title="Test",
            status="open", tools_changed=1, db_path=db_path,
        )
        tc_id = record_pr_tool_change(
            pr_id=pr_id,
            tool_name="read_file",
            original_description="Read a file",
            proposed_description="Read the contents of a specific file.",
            accepted=True,
            db_path=db_path,
        )
        assert tc_id is not None

    def test_pr_stats_in_get_stats(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        record_pr(
            repo="org/repo", pr_number=1, title="PR 1",
            status="open", tools_changed=3, db_path=db_path,
        )
        record_pr(
            repo="org/repo", pr_number=2, title="PR 2",
            status="merged", tools_changed=5, db_path=db_path,
        )
        stats = get_stats(db_path)
        assert stats["total_prs"] == 2
        assert stats["pr_tools_changed"] == 8
        assert stats["pr_status_distribution"]["open"] == 1
        assert stats["pr_status_distribution"]["merged"] == 1

    def test_pr_add_cli(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        runner = CliRunner()
        result = runner.invoke(main, [
            "dataset", "pr-add", "org/repo", "99",
            "-t", "Test PR", "-s", "open", "--tools", "3",
        ])
        assert result.exit_code == 0
        assert "Recorded" in result.output

    def test_pr_list_cli(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "teeshield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        record_pr(
            repo="org/repo", pr_number=1, title="Test",
            status="open", db_path=db_path,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "pr-list"])
        assert result.exit_code == 0
        assert "Tracked Pull Requests" in result.output
