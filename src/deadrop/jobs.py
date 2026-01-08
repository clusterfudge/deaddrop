"""Scheduled jobs for deadrop.

TTL Processing Strategy:
- Run nightly (or on-demand via CLI)
- Phase 1 (current): Mark expired messages as archived, optionally delete
- Phase 2 (future): Export to cold storage (S3/R2) before marking archived
- Phase 3 (future): Support rehydration from cold storage

Cold Storage Design (future):
- Archive batches by namespace + time window
- Store as JSONL files: s3://bucket/deadrop/{ns}/{date}/{batch_id}.jsonl.gz
- Record batch metadata in archive_batches table
- Rehydration: download batch, insert back into messages with archived_at set
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from . import db


def process_ttl(
    archive_path: str | None = None,
    delete: bool = True,
    dry_run: bool = False,
    batch_size: int = 1000,
) -> int:
    """
    Process expired messages.

    Args:
        archive_path: If set, write expired messages to JSONL files here
        delete: Whether to delete expired messages (default True)
        dry_run: If True, just count without modifying
        batch_size: Number of messages to process at a time

    Returns:
        Number of messages processed (deleted or marked archived)
    """
    expired = db.get_expired_messages(limit=batch_size)

    if not expired:
        return 0

    if dry_run:
        return len(expired)

    # Archive if path provided
    if archive_path:
        archive_expired_messages(expired, archive_path)

    # Delete unless asked not to
    if delete:
        return db.delete_expired_messages()

    return 0


def archive_expired_messages(messages: list[dict], archive_path: str) -> str:
    """
    Archive messages to a JSONL file.

    Returns the archive file path.
    """
    if not messages:
        return ""

    path = Path(archive_path)
    path.mkdir(parents=True, exist_ok=True)

    # Group by namespace
    by_ns: dict[str, list[dict]] = {}
    for msg in messages:
        ns = msg["ns"]
        if ns not in by_ns:
            by_ns[ns] = []
        by_ns[ns].append(msg)

    # Write one file per namespace
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    for ns, ns_messages in by_ns.items():
        filename = f"{ns}_{timestamp}.jsonl"
        filepath = path / filename

        with open(filepath, "w") as f:
            for msg in ns_messages:
                f.write(json.dumps(msg) + "\n")

        # Record batch in database
        mids = [m["mid"] for m in ns_messages]
        db.mark_messages_archived(mids, str(filepath))

        db.create_archive_batch(
            ns=ns,
            archive_path=str(filepath),
            message_count=len(ns_messages),
            min_created_at=min(m["created_at"] for m in ns_messages),
            max_created_at=max(m["created_at"] for m in ns_messages),
        )

    return str(path)


# --- Future: Cold Storage ---


def archive_to_s3(
    messages: list[dict],
    bucket: str,
    prefix: str = "deadrop",
) -> str:
    """
    Archive messages to S3/R2 (stub for future implementation).

    Would use boto3 or similar to upload gzipped JSONL.
    Returns the S3 key.
    """
    raise NotImplementedError("S3 archival not yet implemented")


def rehydrate_from_s3(
    bucket: str,
    key: str,
) -> list[dict]:
    """
    Rehydrate messages from S3/R2 archive (stub for future).

    Downloads and decompresses the archive, returns messages.
    """
    raise NotImplementedError("S3 rehydration not yet implemented")


def rehydrate_from_local(archive_path: str) -> list[dict]:
    """
    Rehydrate messages from a local archive file.

    Args:
        archive_path: Path to JSONL archive file

    Returns:
        List of message dicts
    """
    messages = []

    with open(archive_path) as f:
        for line in f:
            if line.strip():
                messages.append(json.loads(line))

    return messages


def rehydrate_namespace(
    ns: str,
    since: str | None = None,
    until: str | None = None,
    archive_base_path: str | None = None,
) -> list[dict]:
    """
    Rehydrate all archived messages for a namespace.

    Looks up archive batches in database and loads from local files.
    Future: support S3/R2 sources.

    Args:
        ns: Namespace to rehydrate
        since: ISO timestamp, only include archives after this time
        until: ISO timestamp, only include archives before this time
        archive_base_path: Override base path for archives

    Returns:
        List of all rehydrated messages
    """
    batches = db.get_archive_batches(ns)
    messages = []

    for batch in batches:
        # Filter by time if specified
        if since and batch["max_created_at"] < since:
            continue
        if until and batch["min_created_at"] > until:
            continue

        # Load from local file
        archive_path = batch["archive_path"]
        if archive_base_path:
            # Reconstruct path with different base
            filename = Path(archive_path).name
            archive_path = str(Path(archive_base_path) / filename)

        try:
            batch_messages = rehydrate_from_local(archive_path)
            messages.extend(batch_messages)
        except FileNotFoundError:
            # Archive file missing - log but continue
            pass

    # Sort by created_at
    messages.sort(key=lambda m: m["created_at"])

    return messages


def export_conversation_view(
    ns: str,
    participants: list[str],
    include_archived: bool = False,
    since: str | None = None,
) -> list[dict]:
    """
    Export messages between specific participants for visualization.

    Returns messages in chronological order, suitable for rendering
    as a conversation timeline.

    Args:
        ns: Namespace
        participants: List of identity IDs to include
        include_archived: Whether to include archived messages
        since: ISO timestamp, only include messages after this time

    Returns:
        List of messages sorted by created_at
    """
    messages = []

    # Get active messages for each participant
    for participant in participants:
        inbox = db.get_messages(ns, participant, mark_as_read=False)
        for msg in inbox:
            if msg["from"] in participants:
                # Apply time filter
                if since and msg["created_at"] < since:
                    continue
                messages.append(msg)

    # Include archived if requested
    if include_archived:
        archived = rehydrate_namespace(ns, since=since)
        for msg in archived:
            if msg["to_id"] in participants and msg["from_id"] in participants:
                messages.append(
                    {
                        "mid": msg["mid"],
                        "from": msg["from_id"],
                        "to": msg["to_id"],
                        "body": msg["body"],
                        "created_at": msg["created_at"],
                        "read_at": msg.get("read_at"),
                        "acked_at": msg.get("acked_at"),
                        "archived": True,
                    }
                )

    # Sort by created_at and dedupe
    seen = set()
    unique = []
    for msg in sorted(messages, key=lambda m: m["created_at"]):
        if msg["mid"] not in seen:
            seen.add(msg["mid"])
            unique.append(msg)

    return unique
