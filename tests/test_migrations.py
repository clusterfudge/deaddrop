"""Tests for database migration system."""

from deadrop import db


class TestSchemaVersionTracking:
    """Tests for schema version tracking functions."""

    def test_get_schema_version_empty_db(self):
        """Empty database should return version 0."""
        conn = db.get_connection()
        # Reset to clean state
        conn.execute("DROP TABLE IF EXISTS schema_version")
        conn.commit()

        version = db.get_schema_version(conn)
        assert version == 0

    def test_record_and_get_migration(self):
        """Recording a migration should update the version."""
        conn = db.get_connection()
        # Reset to clean state
        conn.execute("DROP TABLE IF EXISTS schema_version")
        conn.commit()

        db._ensure_schema_version_table(conn)
        db.record_migration(conn, 1, "Test migration 1")

        version = db.get_schema_version(conn)
        assert version == 1

    def test_multiple_migrations_return_max_version(self):
        """get_schema_version returns the highest version number."""
        conn = db.get_connection()
        # Reset to clean state
        conn.execute("DROP TABLE IF EXISTS schema_version")
        conn.commit()

        db._ensure_schema_version_table(conn)
        db.record_migration(conn, 1, "Test migration 1")
        db.record_migration(conn, 2, "Test migration 2")
        db.record_migration(conn, 3, "Test migration 3")

        version = db.get_schema_version(conn)
        assert version == 3


class TestColumnExists:
    """Tests for column existence checking."""

    def test_column_exists_true(self):
        """_column_exists returns True for existing columns."""
        conn = db.get_connection()
        # namespaces table should exist after init
        db.init_db()

        assert db._column_exists(conn, "namespaces", "ns") is True
        assert db._column_exists(conn, "namespaces", "secret_hash") is True

    def test_column_exists_false(self):
        """_column_exists returns False for non-existing columns."""
        conn = db.get_connection()
        db.init_db()

        assert db._column_exists(conn, "namespaces", "nonexistent_column") is False


class TestMigration001ContentType:
    """Tests for migration 001: add content_type column."""

    def test_migration_adds_column_when_missing(self):
        """Migration 001 adds content_type column to messages table."""
        conn = db.get_connection()

        # Create messages table WITHOUT content_type (simulating old schema)
        conn.executescript("""
            DROP TABLE IF EXISTS messages;
            CREATE TABLE messages (
                mid TEXT PRIMARY KEY,
                ns TEXT NOT NULL,
                to_id TEXT NOT NULL,
                from_id TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                expires_at TIMESTAMP,
                archived_at TIMESTAMP
            );
        """)
        conn.commit()

        # Verify column doesn't exist
        assert db._column_exists(conn, "messages", "content_type") is False

        # Run migration
        db._migrate_001_add_content_type(conn)

        # Verify column now exists
        assert db._column_exists(conn, "messages", "content_type") is True

    def test_migration_is_idempotent(self):
        """Running migration 001 twice should not fail."""
        conn = db.get_connection()

        # Create messages table WITHOUT content_type
        conn.executescript("""
            DROP TABLE IF EXISTS messages;
            CREATE TABLE messages (
                mid TEXT PRIMARY KEY,
                ns TEXT NOT NULL,
                to_id TEXT NOT NULL,
                from_id TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

        # Run migration twice - should not error
        db._migrate_001_add_content_type(conn)
        db._migrate_001_add_content_type(conn)

        assert db._column_exists(conn, "messages", "content_type") is True

    def test_migration_default_value(self):
        """New rows should get 'text/plain' as default content_type."""
        conn = db.get_connection()

        # Create old schema and migrate
        conn.executescript("""
            DROP TABLE IF EXISTS messages;
            CREATE TABLE messages (
                mid TEXT PRIMARY KEY,
                ns TEXT NOT NULL,
                to_id TEXT NOT NULL,
                from_id TEXT NOT NULL,
                body TEXT NOT NULL
            );
        """)
        conn.commit()

        db._migrate_001_add_content_type(conn)

        # Insert a row without specifying content_type
        conn.execute(
            "INSERT INTO messages (mid, ns, to_id, from_id, body) VALUES (?, ?, ?, ?, ?)",
            ("test-mid", "test-ns", "to-id", "from-id", "test body"),
        )
        conn.commit()

        # Verify default value
        cursor = conn.execute("SELECT content_type FROM messages WHERE mid = ?", ("test-mid",))
        row = cursor.fetchone()
        assert row[0] == "text/plain"


class TestRunMigrations:
    """Tests for the migration runner."""

    def test_run_migrations_on_fresh_db(self):
        """run_migrations applies all migrations to a fresh database."""
        conn = db.get_connection()

        # Reset everything
        conn.executescript("""
            DROP TABLE IF EXISTS schema_version;
            DROP TABLE IF EXISTS messages;
            CREATE TABLE messages (
                mid TEXT PRIMARY KEY,
                ns TEXT NOT NULL,
                to_id TEXT NOT NULL,
                from_id TEXT NOT NULL,
                body TEXT NOT NULL
            );
        """)
        conn.commit()

        # Run migrations
        applied = db.run_migrations(conn)

        # Should have applied migration 1
        assert 1 in applied
        assert db.get_schema_version(conn) == 1
        assert db._column_exists(conn, "messages", "content_type") is True

    def test_run_migrations_skips_already_applied(self):
        """run_migrations skips migrations that have already been applied."""
        conn = db.get_connection()

        # Reset and mark migration 1 as already applied
        conn.executescript("""
            DROP TABLE IF EXISTS schema_version;
            DROP TABLE IF EXISTS messages;
            CREATE TABLE messages (
                mid TEXT PRIMARY KEY,
                ns TEXT NOT NULL,
                to_id TEXT NOT NULL,
                from_id TEXT NOT NULL,
                body TEXT NOT NULL,
                content_type TEXT DEFAULT 'text/plain'
            );
        """)
        conn.commit()

        db._ensure_schema_version_table(conn)
        db.record_migration(conn, 1, "Already applied")

        # Run migrations - should apply nothing
        applied = db.run_migrations(conn)

        assert applied == []
        assert db.get_schema_version(conn) == 1

    def test_run_migrations_idempotent(self):
        """Running run_migrations multiple times is safe."""
        conn = db.get_connection()

        # Reset
        conn.executescript("""
            DROP TABLE IF EXISTS schema_version;
            DROP TABLE IF EXISTS messages;
            CREATE TABLE messages (
                mid TEXT PRIMARY KEY,
                ns TEXT NOT NULL,
                to_id TEXT NOT NULL,
                from_id TEXT NOT NULL,
                body TEXT NOT NULL
            );
        """)
        conn.commit()

        # Run migrations twice
        applied1 = db.run_migrations(conn)
        applied2 = db.run_migrations(conn)

        # First run applies migration, second run does nothing
        assert 1 in applied1
        assert applied2 == []
        assert db.get_schema_version(conn) == 1


class TestInitDbWithMigrations:
    """Integration tests for init_db with migrations."""

    def test_init_db_runs_migrations(self):
        """init_db should run migrations after creating tables."""
        # Reset everything
        db.reset_db()

        # init_db is called by reset_db, check that content_type exists
        conn = db.get_connection()
        assert db._column_exists(conn, "messages", "content_type") is True
        assert db.get_schema_version(conn) >= 1

    def test_fresh_db_has_all_columns(self):
        """A fresh database should have all columns including migrated ones."""
        db.reset_db()

        conn = db.get_connection()

        # Check messages table has content_type
        assert db._column_exists(conn, "messages", "content_type") is True

        # Schema version should reflect migrations ran
        assert db.get_schema_version(conn) == db.SCHEMA_VERSION
