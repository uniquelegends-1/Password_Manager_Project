"""End-to-End Encryption (E2EE) helpers with X25519/Argon2id confidentiality & Ed25519 authenticity."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shield_core.key_management import (
    KdfParams,
    derive_kek_argon2id,
    public_key_fingerprint,
    sign_ed25519,
    verify_ed25519,
)

PUBKEY_PREFIX = "SHIELD-PUB-v1:"
SHARE_PK_PREFIX = "SHIELD-E2EE-PK-v1:"
SHARE_PW_PREFIX = "SHIELD-E2EE-PW-v1:"


class E2EEError(Exception):
    """Raised when E2EE key parsing, signature verification, encryption, or decryption fails."""


def generate_x25519_keypair() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(priv_bytes).decode("ascii"),
        PUBKEY_PREFIX + base64.b64encode(pub_bytes).decode("ascii"),
    )


def _parse_public_key(formatted_pub: str) -> X25519PublicKey:
    cleaned = formatted_pub.strip()
    for prefix in (PUBKEY_PREFIX, "VL-PUB-v1:"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    try:
        raw = base64.b64decode(cleaned, validate=True)
        if len(raw) != 32:
            raise ValueError("Invalid key length")
        return X25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise E2EEError("Invalid S.H.I.E.L.D. E2EE public key.") from exc


def _parse_private_key(priv_b64: str) -> X25519PrivateKey:
    try:
        raw = base64.b64decode(priv_b64.strip(), validate=True)
        return X25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise E2EEError("Invalid E2EE private key.") from exc


def _canonical_packet_for_sig(packet: dict[str, Any]) -> bytes:
    """Canonical bytes covered by the sender's Ed25519 signature (excludes 'sig' itself)."""
    body = {k: v for k, v in packet.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _attach_signature(packet: dict[str, Any], priv_b64: str, pub_b64: str) -> None:
    if priv_b64 and pub_b64:
        packet["sender_sig_pub"] = pub_b64
        packet["sig"] = sign_ed25519(priv_b64, _canonical_packet_for_sig(packet))


def _verify_packet_signature(packet: dict[str, Any]) -> str:
    """Verify Ed25519 sender signature if present. Returns verified fingerprint or 'UNSIGNED'."""
    pub = str(packet.get("sender_sig_pub", ""))
    sig = str(packet.get("sig", ""))
    if pub or sig:
        if not pub or not sig:
            raise E2EEError("Authenticity check failed: incomplete Ed25519 signature metadata.")
        if not verify_ed25519(pub, _canonical_packet_for_sig(packet), sig):
            raise E2EEError("Authenticity check failed: invalid Ed25519 sender signature (forged or tampered packet).")
        return public_key_fingerprint(pub)
    return "UNSIGNED"


def encrypt_entry_for_public_key(
    entry_dict: dict[str, Any],
    recipient_public_key: str,
    *,
    sender_signing_priv_b64: str = "",
    sender_signing_pub_b64: str = "",
) -> str:
    recipient_pub = _parse_public_key(recipient_public_key)
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_secret = ephemeral_priv.exchange(recipient_pub)

    salt = os.urandom(16)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"shield-e2ee-share-v1",
    ).derive(shared_secret)

    nonce = os.urandom(12)
    aad = ephemeral_pub_bytes + salt
    plaintext = json.dumps(entry_dict, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

    packet: dict[str, Any] = {
        "v": 1,
        "mode": "x25519",
        "epk": base64.b64encode(ephemeral_pub_bytes).decode("ascii"),
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }
    _attach_signature(packet, sender_signing_priv_b64, sender_signing_pub_b64)
    encoded = base64.urlsafe_b64encode(json.dumps(packet, separators=(",", ":")).encode("utf-8")).decode(
        "ascii"
    )
    return SHARE_PK_PREFIX + encoded


def decrypt_entry_with_private_key(
    token: str, recipient_private_key_b64: str
) -> tuple[dict[str, Any], str]:
    """Decrypt and verify authenticity of an X25519 E2EE packet. Returns (entry_dict, sender_fingerprint)."""
    cleaned = token.strip()
    if not cleaned.startswith(SHARE_PK_PREFIX):
        raise E2EEError("Not a valid S.H.I.E.L.D. public-key E2EE packet.")

    try:
        payload_json = base64.urlsafe_b64decode(cleaned[len(SHARE_PK_PREFIX) :].encode("ascii"))
        packet = json.loads(payload_json.decode("utf-8"))
        epk_bytes = base64.b64decode(packet["epk"], validate=True)
        salt = base64.b64decode(packet["salt"], validate=True)
        nonce = base64.b64decode(packet["nonce"], validate=True)
        ciphertext = base64.b64decode(packet["ct"], validate=True)
    except Exception as exc:
        raise E2EEError("Corrupted or malformed E2EE packet.") from exc

    sender_fp = _verify_packet_signature(packet)

    recipient_priv = _parse_private_key(recipient_private_key_b64)
    try:
        epk = X25519PublicKey.from_public_bytes(epk_bytes)
        shared_secret = recipient_priv.exchange(epk)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"shield-e2ee-share-v1",
        ).derive(shared_secret)
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, epk_bytes + salt)
        return json.loads(plaintext.decode("utf-8")), sender_fp
    except InvalidTag as exc:
        raise E2EEError("Decryption failed: packet was not encrypted for your vault key or was tampered with.") from exc
    except Exception as exc:
        raise E2EEError(f"Could not decrypt E2EE packet: {exc}") from exc


def encrypt_entry_with_passphrase(
    entry_dict: dict[str, Any],
    passphrase: str,
    *,
    sender_signing_priv_b64: str = "",
    sender_signing_pub_b64: str = "",
) -> str:
    if len(passphrase) < 6:
        raise E2EEError("Share passphrase must be at least 6 characters long.")
    salt = os.urandom(16)
    kdf_params = KdfParams(iterations=2, memory_cost=32768, lanes=2)
    aes_key = derive_kek_argon2id(passphrase, salt, kdf_params)
    nonce = os.urandom(12)
    kdf_dict = kdf_params.to_dict()
    aad = salt + json.dumps(kdf_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plaintext = json.dumps(entry_dict, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

    packet: dict[str, Any] = {
        "v": 1,
        "mode": "argon2id-passphrase",
        "kdf": kdf_dict,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }
    _attach_signature(packet, sender_signing_priv_b64, sender_signing_pub_b64)
    encoded = base64.urlsafe_b64encode(json.dumps(packet, separators=(",", ":")).encode("utf-8")).decode(
        "ascii"
    )
    return SHARE_PW_PREFIX + encoded


def decrypt_entry_with_passphrase(token: str, passphrase: str) -> tuple[dict[str, Any], str]:
    """Decrypt and verify authenticity of a passphrase E2EE packet. Returns (entry_dict, sender_fingerprint)."""
    cleaned = token.strip()
    if not cleaned.startswith(SHARE_PW_PREFIX):
        raise E2EEError("Not a valid S.H.I.E.L.D. passphrase E2EE packet.")

    try:
        payload_json = base64.urlsafe_b64decode(cleaned[len(SHARE_PW_PREFIX) :].encode("ascii"))
        packet = json.loads(payload_json.decode("utf-8"))
        kdf_params = KdfParams.from_dict(packet["kdf"])
        salt = base64.b64decode(packet["salt"], validate=True)
        nonce = base64.b64decode(packet["nonce"], validate=True)
        ciphertext = base64.b64decode(packet["ct"], validate=True)
    except Exception as exc:
        raise E2EEError("Corrupted or malformed passphrase E2EE packet.") from exc

    sender_fp = _verify_packet_signature(packet)

    aes_key = derive_kek_argon2id(passphrase, salt, kdf_params)
    aad = salt + json.dumps(kdf_params.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
        return json.loads(plaintext.decode("utf-8")), sender_fp
    except InvalidTag as exc:
        raise E2EEError("Incorrect share passphrase or tampered packet.") from exc
    except Exception as exc:
        raise E2EEError(f"Could not decrypt E2EE packet: {exc}") from exc
