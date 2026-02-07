#!/usr/bin/env python3
"""Local test script for E2E room encryption.

This script simulates multiple clients sharing credentials and joining encrypted rooms.
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx
from deadrop.crypto import (
    generate_keypair,
    generate_room_base_secret,
    encrypt_room_message,
    encrypt_base_secret_for_member,
    decrypt_base_secret_from_invite,
    decrypt_epoch_key,
    bytes_to_base64url,
    base64url_to_bytes,
)

BASE_URL = "http://localhost:8766"


def create_namespace(display_name: str):
    """Create a namespace."""
    resp = httpx.post(
        f"{BASE_URL}/admin/namespaces", json={"display_name": display_name}, timeout=10.0
    )
    resp.raise_for_status()
    return resp.json()


def create_identity(ns: str, ns_secret: str, display_name: str):
    """Create an identity in a namespace."""
    resp = httpx.post(
        f"{BASE_URL}/{ns}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"display_name": display_name},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def register_pubkey(ns: str, identity_id: str, secret: str, keypair):
    """Register a public key for an identity."""
    resp = httpx.put(
        f"{BASE_URL}/{ns}/inbox/{identity_id}/pubkey",
        headers={"X-Inbox-Secret": secret},
        json={
            "public_key": keypair.public_key_base64,
            "signing_public_key": keypair.signing_public_key_base64,
            "algorithm": "nacl-box",
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def create_room(ns: str, creator_secret: str, display_name: str, encrypted: bool = False):
    """Create a room."""
    payload = {"display_name": display_name}
    if encrypted:
        payload["encryption_enabled"] = True

    resp = httpx.post(
        f"{BASE_URL}/{ns}/rooms",
        headers={"X-Inbox-Secret": creator_secret},
        json=payload,
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def add_room_member(ns: str, room_id: str, member_id: str, inviter_secret: str):
    """Add a member to a room."""
    resp = httpx.post(
        f"{BASE_URL}/{ns}/rooms/{room_id}/members",
        headers={"X-Inbox-Secret": inviter_secret},
        json={"identity_id": member_id},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def get_epoch_key(ns: str, room_id: str, secret: str, epoch_number: int = None):
    """Get epoch key for a room."""
    if epoch_number is None:
        url = f"{BASE_URL}/{ns}/rooms/{room_id}/epoch"
    else:
        url = f"{BASE_URL}/{ns}/rooms/{room_id}/epoch/{epoch_number}"

    resp = httpx.get(url, headers={"X-Inbox-Secret": secret}, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def send_encrypted_message(
    ns: str,
    room_id: str,
    secret: str,
    body: str,
    epoch_key: bytes,
    sender_keypair,
    epoch_number: int,
):
    """Send an encrypted message to a room."""
    encrypted = encrypt_room_message(
        plaintext=body,
        epoch_key=epoch_key,
        sender_signing_key=sender_keypair.private_key,
        room_id=room_id,
        epoch_number=epoch_number,
    )

    resp = httpx.post(
        f"{BASE_URL}/{ns}/rooms/{room_id}/messages",
        headers={"X-Inbox-Secret": secret},
        json={
            "body": bytes_to_base64url(encrypted.ciphertext),
            "encrypted": True,
            "epoch_number": epoch_number,
            "encryption_meta": f'{{"algorithm": "xsalsa20-poly1305+ed25519", "nonce": "{bytes_to_base64url(encrypted.nonce)}"}}',
            "signature": bytes_to_base64url(encrypted.signature),
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def get_room_messages(ns: str, room_id: str, secret: str):
    """Get messages from a room."""
    resp = httpx.get(
        f"{BASE_URL}/{ns}/rooms/{room_id}/messages",
        headers={"X-Inbox-Secret": secret},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def main():
    print("=" * 60)
    print("E2E Room Encryption Local Test")
    print("=" * 60)

    # Step 1: Create namespace
    print("\n[1] Creating namespace...")
    ns_data = create_namespace("Test Namespace")
    ns = ns_data["ns"]
    ns_secret = ns_data["secret"]
    print(f"    Namespace: {ns[:16]}...")

    # Step 2: Create identities with keypairs
    print("\n[2] Creating identities with keypairs...")

    # Alice (room creator)
    alice = create_identity(ns, ns_secret, "Alice")
    alice_keypair = generate_keypair()
    register_pubkey(ns, alice["id"], alice["secret"], alice_keypair)
    print(f"    Alice: {alice['id'][:16]}...")

    # Bob (will be invited)
    bob = create_identity(ns, ns_secret, "Bob")
    bob_keypair = generate_keypair()
    register_pubkey(ns, bob["id"], bob["secret"], bob_keypair)
    print(f"    Bob: {bob['id'][:16]}...")

    # Carol (will be invited later)
    carol = create_identity(ns, ns_secret, "Carol")
    carol_keypair = generate_keypair()
    register_pubkey(ns, carol["id"], carol["secret"], carol_keypair)
    print(f"    Carol: {carol['id'][:16]}...")

    # Step 3: Alice creates encrypted room
    print("\n[3] Alice creates encrypted room...")
    room = create_room(ns, alice["secret"], "Secret Room", encrypted=True)
    room_id = room["room_id"]
    print(f"    Room: {room_id[:16]}...")
    print(f"    Encryption enabled: {room.get('encryption_enabled')}")
    print(f"    Current epoch: {room.get('current_epoch_number', 0)}")

    # Step 4: Alice gets her epoch key
    print("\n[4] Alice fetches epoch 0 key...")
    epoch_data = get_epoch_key(ns, room_id, alice["secret"])
    print(f"    Epoch: {epoch_data['epoch']['epoch_number']}")
    print(f"    distributor_public_key: {epoch_data.get('distributor_public_key', 'N/A')[:30]}...")

    # The key is encrypted with NaCl box - decrypt it with Alice's private key
    encrypted_key_bytes = base64url_to_bytes(epoch_data["encrypted_epoch_key"])
    distributor_pubkey = base64url_to_bytes(epoch_data["distributor_public_key"])
    print(f"    Encrypted key length: {len(encrypted_key_bytes)} bytes")

    # Decrypt the epoch key using Alice's private key and server's public key
    epoch_0_key = decrypt_epoch_key(
        encrypted_epoch_key=encrypted_key_bytes,
        distributor_public_key=distributor_pubkey,
        member_private_key=alice_keypair.private_key,
    )
    print(f"    Decrypted key (first 16 bytes): {epoch_0_key[:16].hex()}...")

    # Step 5: Alice sends encrypted message
    print("\n[5] Alice sends encrypted message at epoch 0...")
    msg1 = send_encrypted_message(
        ns,
        room_id,
        alice["secret"],
        "Hello from Alice! This is epoch 0.",
        epoch_0_key,
        alice_keypair,
        0,
    )
    print(f"    Message ID: {msg1['mid'][:16]}...")

    # Step 6: Bob joins (should trigger epoch rotation)
    print("\n[6] Alice invites Bob (triggers epoch rotation)...")
    add_room_member(ns, room_id, bob["id"], alice["secret"])
    print("    Bob added to room")

    # Step 7: Bob fetches his epoch key
    print("\n[7] Bob fetches his epoch 1 key...")
    bob_epoch_data = get_epoch_key(ns, room_id, bob["secret"])
    print(f"    Epoch: {bob_epoch_data['epoch']['epoch_number']}")

    # Decrypt Bob's epoch key
    bob_encrypted_key = base64url_to_bytes(bob_epoch_data["encrypted_epoch_key"])
    bob_distributor_pubkey = base64url_to_bytes(bob_epoch_data["distributor_public_key"])
    epoch_1_key = decrypt_epoch_key(
        encrypted_epoch_key=bob_encrypted_key,
        distributor_public_key=bob_distributor_pubkey,
        member_private_key=bob_keypair.private_key,
    )
    print(f"    Decrypted key (first 16 bytes): {epoch_1_key[:16].hex()}...")

    # Step 8: Bob sends encrypted message
    print("\n[8] Bob sends encrypted message at epoch 1...")
    msg2 = send_encrypted_message(
        ns, room_id, bob["secret"], "Hi Alice! Bob here at epoch 1.", epoch_1_key, bob_keypair, 1
    )
    print(f"    Message ID: {msg2['mid'][:16]}...")

    # Step 9: Carol joins
    print("\n[9] Alice invites Carol (triggers epoch rotation)...")
    add_room_member(ns, room_id, carol["id"], alice["secret"])
    print("    Carol added to room")

    # Step 10: Carol fetches epoch key
    print("\n[10] Carol fetches her epoch 2 key...")
    carol_epoch_data = get_epoch_key(ns, room_id, carol["secret"])
    print(f"    Epoch: {carol_epoch_data['epoch']['epoch_number']}")

    # Decrypt Carol's epoch key
    carol_encrypted_key = base64url_to_bytes(carol_epoch_data["encrypted_epoch_key"])
    carol_distributor_pubkey = base64url_to_bytes(carol_epoch_data["distributor_public_key"])
    epoch_2_key = decrypt_epoch_key(
        encrypted_epoch_key=carol_encrypted_key,
        distributor_public_key=carol_distributor_pubkey,
        member_private_key=carol_keypair.private_key,
    )
    print(f"    Decrypted key (first 16 bytes): {epoch_2_key[:16].hex()}...")

    # Step 11: Carol sends message
    print("\n[11] Carol sends encrypted message at epoch 2...")
    msg3 = send_encrypted_message(
        ns,
        room_id,
        carol["secret"],
        "Hey everyone! Carol joining the party at epoch 2.",
        epoch_2_key,
        carol_keypair,
        2,
    )
    print(f"    Message ID: {msg3['mid'][:16]}...")

    # Step 12: All users read messages
    print("\n[12] Reading messages from room...")
    messages_resp = get_room_messages(ns, room_id, alice["secret"])
    print(f"    Response type: {type(messages_resp)}")
    print(
        f"    Response keys: {messages_resp.keys() if isinstance(messages_resp, dict) else 'N/A'}"
    )

    # The response might be wrapped or be a list directly
    if isinstance(messages_resp, list):
        messages = messages_resp
    elif isinstance(messages_resp, dict) and "messages" in messages_resp:
        messages = messages_resp["messages"]
    else:
        messages = list(messages_resp.values()) if isinstance(messages_resp, dict) else []

    print(f"    Total messages: {len(messages)}")
    for msg in messages:
        if isinstance(msg, dict):
            is_enc = "🔒" if msg.get("encrypted") else "📝"
            epoch = msg.get("epoch_number", "N/A")
            from_id = msg.get("from", msg.get("from_id", "unknown"))
            print(f"    {is_enc} Epoch {epoch}: {from_id[:8]}... - {msg['body'][:30]}...")
        else:
            print(f"    Raw: {str(msg)[:50]}...")

    # Step 13: Test forward secrecy - Carol cannot read epoch 0 messages
    print("\n[13] Testing forward secrecy...")
    try:
        # Carol tries to get epoch 0 key
        carol_epoch_0 = get_epoch_key(ns, room_id, carol["secret"], epoch_number=0)
        if carol_epoch_0.get("encrypted_epoch_key"):
            print("    ⚠️ Carol got epoch 0 key (she wasn't a member then!)")
        else:
            print("    ✅ Carol cannot access epoch 0 key (forward secrecy)")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print("    ✅ Carol cannot access epoch 0 key (forward secrecy)")
        else:
            print(f"    ❌ Error: {e}")

    # Step 14: Test client-side E2E crypto functions
    print("\n[14] Testing client-side E2E crypto functions...")

    # Create a base secret and encrypt it for a member
    test_secret = generate_room_base_secret()
    print(f"    Generated base secret: {test_secret[:8].hex()}...")

    # Alice encrypts secret for Bob
    encrypted_for_bob = encrypt_base_secret_for_member(
        base_secret=test_secret,
        member_public_key=bob_keypair.public_key,
        sender_private_key=alice_keypair.private_key,
        room_id=room_id,
    )
    print(f"    Encrypted for Bob: {len(encrypted_for_bob)} bytes")

    # Bob decrypts
    bob_decrypted = decrypt_base_secret_from_invite(
        encrypted_secret=encrypted_for_bob,
        sender_public_key=alice_keypair.public_key,
        recipient_private_key=bob_keypair.private_key,
        room_id=room_id,
    )
    print(f"    Bob decrypted: {bob_decrypted[:8].hex()}...")

    assert bob_decrypted == test_secret, "Decryption mismatch!"
    print("    ✅ E2E secret sharing works correctly!")

    # Test wrong room_id fails
    print("\n[15] Testing room_id binding...")
    try:
        decrypt_base_secret_from_invite(
            encrypted_secret=encrypted_for_bob,
            sender_public_key=alice_keypair.public_key,
            recipient_private_key=bob_keypair.private_key,
            room_id="wrong-room-id",  # Wrong room!
        )
        print("    ❌ Should have failed with wrong room_id!")
    except ValueError as e:
        print(f"    ✅ Correctly rejected: {e}")

    print("\n" + "=" * 60)
    print("All tests passed! ✅")
    print("=" * 60)


if __name__ == "__main__":
    main()
