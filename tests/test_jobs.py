"""Tests for deadrop scheduled jobs."""

from datetime import datetime, timedelta, timezone

import pytest

from deadrop import db
from deadrop import jobs


def create_test_namespace():
    """Create a test namespace, return {ns, secret}."""
    return db.create_namespace({"display_name": "Test"})


def create_test_identity(ns: str):
    """Create a test identity, return {id, secret}."""
    return db.create_identity(ns, {"display_name": "Test Agent"})


def expire_message_immediately(ns: str, to_id: str, mid: str):
    """Helper to expire a message immediately for testing."""
    conn = db.get_connection()
    past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn.execute(
        "UPDATE messages SET expires_at = ? WHERE ns = ? AND to_id = ? AND mid = ?",
        (past_time, ns, to_id, mid)
    )
    conn.commit()


class TestTTLProcessing:
    def test_no_expired_messages(self):
        """No messages are deleted when none have expired."""
        ns_data = create_test_namespace()
        agent1 = create_test_identity(ns_data["ns"])
        agent2 = create_test_identity(ns_data["ns"])
        
        # Send message (no TTL set yet - not read)
        db.send_message(
            ns=ns_data["ns"],
            from_id=agent1["id"],
            to_id=agent2["id"],
            body="hello",
        )
        
        deleted = jobs.process_ttl()
        assert deleted == 0

    def test_expired_messages_deleted(self):
        """Expired messages are deleted."""
        ns_data = create_test_namespace()
        agent1 = create_test_identity(ns_data["ns"])
        agent2 = create_test_identity(ns_data["ns"])
        
        # Send message
        result = db.send_message(
            ns=ns_data["ns"],
            from_id=agent1["id"],
            to_id=agent2["id"],
            body="hello",
        )
        mid = result["mid"]
        
        # Read the message (starts TTL)
        db.get_messages(ns_data["ns"], agent2["id"])
        
        # Force expire it
        expire_message_immediately(ns_data["ns"], agent2["id"], mid)
        
        # Process TTL
        deleted = jobs.process_ttl()
        assert deleted == 1
        
        # Verify message is gone
        conn = db.get_connection()
        row = conn.execute(
            "SELECT * FROM messages WHERE mid = ?", (mid,)
        ).fetchone()
        assert row is None

    def test_expired_messages_archived_not_deleted(self):
        """Messages can be archived instead of deleted."""
        import os
        import tempfile
        
        ns_data = create_test_namespace()
        agent1 = create_test_identity(ns_data["ns"])
        agent2 = create_test_identity(ns_data["ns"])
        
        # Send message
        result = db.send_message(
            ns=ns_data["ns"],
            from_id=agent1["id"],
            to_id=agent2["id"],
            body="hello",
        )
        mid = result["mid"]
        
        # Read the message (starts TTL)
        db.get_messages(ns_data["ns"], agent2["id"])
        
        # Force expire it
        expire_message_immediately(ns_data["ns"], agent2["id"], mid)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Process with archive but no delete
            jobs.process_ttl(archive_path=tmpdir, delete=False)
            
            # Archive file should exist
            archive_files = [f for f in os.listdir(tmpdir) if f.endswith('.jsonl')]
            assert len(archive_files) == 1
            
            # Message should still exist (not deleted)
            conn = db.get_connection()
            row = conn.execute(
                "SELECT * FROM messages WHERE mid = ?", (mid,)
            ).fetchone()
            assert row is not None

    def test_dry_run(self):
        """Dry run shows count but doesn't delete."""
        ns_data = create_test_namespace()
        agent1 = create_test_identity(ns_data["ns"])
        agent2 = create_test_identity(ns_data["ns"])
        
        # Send message
        result = db.send_message(
            ns=ns_data["ns"],
            from_id=agent1["id"],
            to_id=agent2["id"],
            body="hello",
        )
        
        # Read the message (starts TTL)
        db.get_messages(ns_data["ns"], agent2["id"])
        
        # Force expire it
        expire_message_immediately(ns_data["ns"], agent2["id"], result["mid"])
        
        # Dry run
        count = jobs.process_ttl(dry_run=True)
        assert count == 1
        
        # Message should still exist
        conn = db.get_connection()
        row = conn.execute(
            "SELECT * FROM messages WHERE mid = ?", (result["mid"],)
        ).fetchone()
        assert row is not None


class TestArchiveBatches:
    def test_archive_batch_recorded(self):
        """Archive batches are recorded in database."""
        import tempfile
        
        ns_data = create_test_namespace()
        agent1 = create_test_identity(ns_data["ns"])
        agent2 = create_test_identity(ns_data["ns"])
        
        # Send message
        result = db.send_message(
            ns=ns_data["ns"],
            from_id=agent1["id"],
            to_id=agent2["id"],
            body="hello",
        )
        
        # Read the message (starts TTL)
        db.get_messages(ns_data["ns"], agent2["id"])
        
        # Force expire it
        expire_message_immediately(ns_data["ns"], agent2["id"], result["mid"])
        
        with tempfile.TemporaryDirectory() as tmpdir:
            jobs.process_ttl(archive_path=tmpdir)
            
            batches = db.get_archive_batches(ns_data["ns"])
            assert len(batches) == 1
            assert batches[0]["message_count"] == 1
