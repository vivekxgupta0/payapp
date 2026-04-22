# OfflinePay Security Architecture — BLE Offline UPI Payment System

## Compliance Targets
- RBI Master Direction on Digital Payments Security Controls (2021)
- NPCI UPI Lite / Offline Payments Framework
- PCI DSS v4.0 (relevant sections for mobile payments)

---

## 1. Threat Model

| # | Threat | Attack Vector | Severity | Mitigation | Implementation |
|---|--------|---------------|----------|-----------|----------------|
| T1 | **Replay Attack** | Attacker captures a signed BLE transaction and re-transmits it | CRITICAL | Unique nonce per txn + timestamp expiry window (5 min) + server-side nonce dedup + monotonic counter | `NonceTracker` (SQLite) + backend `Transaction.nonce` UNIQUE constraint |
| T2 | **Device Spoofing** | Fake merchant/payer app impersonates a real user | CRITICAL | Hardware-backed ECDSA P-256 keypair per device, device binding via public key registration with backend, mutual authentication over BLE | `DeviceKeyService` (Android Keystore / iOS Secure Enclave) |
| T3 | **MITM over BLE** | Attacker intercepts BLE packets between sender/receiver | HIGH | ECDH ephemeral key exchange → AES-256-GCM session encryption + mutual challenge-response authentication | `CryptoService` + `SecureBLEProtocol` |
| T4 | **Double Spending** | User makes multiple offline payments exceeding their limit | CRITICAL | Immediate local balance deduction + monotonic sequence numbers + server reconciliation with first-valid-wins | `SecureTransactionEngine` + backend `ReconciliationService` |
| T5 | **Key Extraction** | Attacker roots device and extracts signing keys | HIGH | Hardware-backed keystore (keys never leave TEE/SE), root/jailbreak detection → offline mode kill switch | `DeviceKeyService` + `DeviceIntegrityService` |
| T6 | **Packet Sniffing** | Passive BLE listener captures transaction details | MEDIUM | AES-256-GCM encryption on all BLE payloads, ephemeral keys per session | `CryptoService` |
| T7 | **Signature Forgery** | Attacker creates fake signed transactions | CRITICAL | ECDSA P-256 signatures verified by backend using registered public key, reject unknown keys | Backend `signature_verification.py` |
| T8 | **Emulator/Debug Attack** | Run app in emulator to bypass security controls | HIGH | Emulator detection, debug mode detection, disable offline features | `DeviceIntegrityService` |
| T9 | **Blob Tampering** | Modify blob amount/receiver after signing | CRITICAL | ECDSA signature covers full transaction payload (txn_id + payer + payee + amount + timestamp + nonce), any modification invalidates signature | `SecureTransactionEngine.signTransaction()` |
| T10 | **Limit Bypass** | Tamper with locally cached offline limit | HIGH | Server-signed limit certificate with expiry, verified locally before payment | Backend-signed limit token |
| T11 | **Stale Transaction** | Submit very old offline transaction | MEDIUM | 5-minute BLE window + 72-hour max sync window + backend rejects older | Timestamp validation at both layers |
| T12 | **Data Theft at Rest** | Steal SQLite database from device | HIGH | SQLCipher encryption for local database, sensitive fields in OS secure storage | `EncryptedStorage` |

---

## 2. Architecture Diagram (Text-Based)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SENDER DEVICE                                │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────────┐    │
│  │ Android      │  │ DeviceKeyService │  │ CryptoService      │    │
│  │ Keystore /   │──│ ECDSA P-256      │──│ ECDH + AES-256-GCM │    │
│  │ iOS Secure   │  │ Device Binding   │  │ + ECDSA Signing    │    │
│  │ Enclave      │  └──────────────────┘  └────────────────────┘    │
│  └──────────────┘           │                      │                │
│                             ▼                      ▼                │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              SecureBLEProtocol                            │      │
│  │  1. Exchange ephemeral ECDH public keys                  │      │
│  │  2. Derive AES-256 session key (HKDF)                    │      │
│  │  3. Mutual authentication (challenge-response)           │      │
│  │  4. Encrypt + Sign transaction payload                   │      │
│  │  5. Transmit via BLE GATT                                │      │
│  └──────────────────────────────────────────────────────────┘      │
│                             │                                       │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              SecureTransactionEngine                      │      │
│  │  - NPCI-compliant limits (₹2000/txn, ₹4000/day)         │      │
│  │  - Nonce tracking + timestamp validation                 │      │
│  │  - Immediate local balance deduction                     │      │
│  │  - Signed transaction blobs → SQLCipher queue            │      │
│  └──────────────────────────────────────────────────────────┘      │
│                             │                                       │
│  ┌──────────────────┐  ┌───────────────────┐                       │
│  │ DeviceIntegrity  │  │ Encrypted SQLite  │                       │
│  │ Root/Emulator    │  │ (SQLCipher)       │                       │
│  │ Detection        │  │ + SecureStorage   │                       │
│  └──────────────────┘  └───────────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
                              │ BLE (AES-256-GCM encrypted)
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       RECEIVER DEVICE                               │
│         (Same security stack, receives + stores blob)               │
└─────────────────────────────────────────────────────────────────────┘
                              │ When online
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         BACKEND                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              POST /api/offline/sync                       │      │
│  │  1. Verify ECDSA signature against registered public key │      │
│  │  2. Check nonce uniqueness (UNIQUE constraint)            │      │
│  │  3. Validate timestamp within 72-hour window              │      │
│  │  4. Run fraud detection (velocity, amount, patterns)      │      │
│  │  5. First-valid-wins conflict resolution                  │      │
│  │  6. Settle: debit sender, credit receiver                │      │
│  │  7. Return per-blob status + new signed limit             │      │
│  └──────────────────────────────────────────────────────────┘      │
│  ┌──────────────────┐  ┌──────────────────┐                        │
│  │ Device Registry  │  │ ECDSA Public Key │                        │
│  │ (user↔device     │  │ Store            │                        │
│  │  binding)        │  │                  │                        │
│  └──────────────────┘  └──────────────────┘                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. API Contracts (Security-Enhanced)

### POST /api/device/register
Register device public key for device binding.
```json
Request: {
  "device_id": "uuid",
  "public_key_pem": "base64-encoded ECDSA P-256 public key",
  "device_info": { "platform": "android|ios", "os_version": "..." }
}
Response: { "status": "bound", "device_id": "..." }
```

### POST /api/offline/sync (enhanced)
```json
Request: {
  "blobs": [{
    "id": "uuid",
    "sender_id": "user_id",
    "receiver_id": "user_id",
    "amount": 150.0,
    "timestamp": "ISO8601",
    "nonce": "uuid",
    "sequence_number": 42,
    "signature": "base64-ECDSA-signature-over-canonical-payload",
    "sender_public_key": "base64-encoded",
    "is_offline": true,
    "offline_limit_at_time": 2000.0
  }]
}
Response: {
  "results": [
    { "id": "uuid", "status": "accepted|rejected|duplicate", "message": "..." }
  ],
  "new_offline_limit": 1850.0,
  "limit_expiry": "ISO8601",
  "limit_signature": "base64-server-signature-over-limit"
}
```

### GET /api/user/offline-limit (enhanced)
```json
Response: {
  "limit": 2000.0,
  "expiry": "ISO8601",
  "risk_score": 0.35,
  "limit_signature": "base64-Ed25519-signature-over-limit+expiry+userId"
}
```

---

## 4. NPCI Compliance Checklist

| # | Requirement | Status | Implementation |
|---|------------|--------|----------------|
| 1 | End-to-end encryption | ✔ | AES-256-GCM for BLE, TLS for HTTP |
| 2 | Device binding | ✔ | Hardware keystore ECDSA P-256 |
| 3 | Transaction signing | ✔ | ECDSA signature on every transaction |
| 4 | Per-transaction limit | ✔ | ₹2000 max per offline transaction |
| 5 | Daily cumulative limit | ✔ | ₹4000 max per day offline |
| 6 | Balance cap | ✔ | ₹5000 max offline credit limit |
| 7 | Nonce/replay protection | ✔ | UUID nonce + 5-min BLE window + server dedup |
| 8 | Audit logs | ✔ | LedgerEntry table + device-side encrypted log |
| 9 | Root/jailbreak detection | ✔ | DeviceIntegrityService with kill switch |
| 10 | Mutual authentication | ✔ | Challenge-response over BLE before txn |
| 11 | Offline mode expiry | ✔ | 24-hour limit expiry, 72-hour max sync window |
| 12 | Fraud detection | ✔ | ML risk engine + velocity + pattern checks |
| 13 | Data at rest encryption | ✔ | flutter_secure_storage + encrypted DB |
| 14 | Key non-exportability | ✔ | Hardware-backed keys never leave TEE |

### Known Gaps & Mitigations
| Gap | Risk | Mitigation Plan |
|-----|------|----------------|
| No HSM for backend signing keys | Medium | Use AWS KMS / GCP Cloud KMS in production |
| BLE peripheral on Android needs native plugin | Low | Implement Android MethodChannel equivalent of iOS AppDelegate BLE code |
| No certificate pinning on HTTP | Medium | Add certificate pinning for production API endpoints |
| Demo JWT secret is hardcoded | HIGH | Must use env-injected secret in production |
| Software key fallback when native keystore unavailable | Medium | Acceptable for rural low-end devices; keys stored in flutter_secure_storage (Keychain/EncryptedSharedPrefs) |
| No UPI VPA mapping (simulated) | Low | Integrate with NPCI VPA resolution API in production |

---

## 5. Pseudocode — Transaction Signing

```
function createSignedTransaction(senderId, receiverId, amount):
    // Pre-flight checks
    error = validateOfflinePayment(amount, senderId, receiverId)
    if error != null: return FAIL(error)

    // Create blob
    blob = PaymentBlob(
        id: uuid(),
        senderId: senderId,
        receiverId: receiverId,
        amount: amount,
        timestamp: now_utc(),
        nonce: uuid(),
        status: PENDING_SYNC,
        isOffline: true,
        offlineLimitAtTime: getAvailableLimit()
    )

    // Build canonical payload (deterministic string)
    canonical = "{blob.id}|{senderId}|{receiverId}|{amount:.2f}|{timestamp_utc}|{nonce}"

    // Sign with device ECDSA P-256 key (hardware-backed)
    signature = ECDSA_SIGN(SHA256(canonical), device_private_key)

    // Deduct immediately (double-spend prevention)
    deductFromOfflineLimit(amount)
    incrementDailyTotal(amount)

    // Store in encrypted SQLite queue
    enqueueBlob(blob with signature)

    // Track nonce for replay detection
    recordNonce(blob.nonce)

    return SUCCESS(signedBlob)
```

## 6. Pseudocode — BLE Handshake

```
== SENDER (Central) ==                    == RECEIVER (Peripheral) ==

1. Scan for BLE device matching
   session UUID from QR code
                                          1. Generate session UUID
                                          2. Start BLE advertising
                                          3. Embed UUID in QR code

2. Connect to device
3. Generate ephemeral ECDH keypair
4. Send ECDH public key
   [0x01 | ephemeral_pub_bytes]
                                          5. Receive sender's ECDH pub key
                                          6. Generate own ephemeral keypair
                                          7. Derive shared secret = ECDH(own_priv, sender_pub)
                                          8. Derive session key = HKDF-SHA256(shared_secret)
                                          9. Send own ECDH pub key back
                                          10. Generate 32-byte challenge
                                          11. Send challenge
                                             [0x02 | challenge_bytes]

5. Receive receiver's pub key
6. Derive shared secret = ECDH(own_priv, receiver_pub)
7. Derive session key = HKDF-SHA256(shared_secret)
8. Receive challenge
9. Compute response = HMAC-SHA256(session_key, challenge || sender_id)
10. Send response
    [0x03 | identity_len | identity | hmac_response]
                                          12. Verify challenge response
                                          13. If valid → send ACK [0x05 | "OK"]
                                          14. If invalid → send ERROR, disconnect

11. Receive ACK (mutual auth complete)
12. Sign blob with ECDSA device key
13. Encrypt blob with AES-256-GCM(session_key)
14. Send encrypted blob
    [0x04 | IV(12) | ciphertext | tag(16)]
                                          15. Decrypt blob with AES-256-GCM
                                          16. Verify ECDSA signature
                                          17. Validate timestamp (< 5 min)
                                          18. Check nonce uniqueness
                                          19. Store in local queue
                                          20. Send encrypted ACK

15. Receive ACK → disconnect
```

## 7. Pseudocode — Backend Reconciliation

```
function syncOfflineBlobs(blobs[], currentUser):
    results = []
    dailyTotal = 0

    for blob in blobs:
        // 1. Idempotency
        if existsInDB(blob.nonce): result = DUPLICATE; continue

        // 2. Timestamp validation (72-hour window)
        if age(blob.timestamp) > 72h: result = REJECTED("too old"); continue

        // 3. Global nonce uniqueness
        if nonceRegistry.has(blob.nonce): result = REJECTED("replay"); continue

        // 4. ECDSA signature verification
        deviceBinding = lookupDeviceBinding(blob.senderPublicKey)
        if !verifyECDSA(canonical(blob), blob.signature, deviceBinding.publicKey):
            result = REJECTED("bad signature"); continue

        // 5. NPCI limits
        if blob.amount > 2000: result = REJECTED("per-txn limit"); continue
        if dailyTotal + blob.amount > 4000: result = REJECTED("daily limit"); continue

        // 6. Fraud heuristics
        if isSuspicious(blob): result = REJECTED("fraud"); continue

        // 7. Balance check
        sender = lookupUser(blob.senderId)
        if sender.balance < blob.amount: result = REJECTED("insufficient"); continue

        // 8. SETTLE (first-valid-wins)
        sender.balance -= blob.amount
        receiver.balance += blob.amount
        createTransaction(blob)
        createLedgerEntries(sender, receiver)
        registerNonce(blob.nonce)
        dailyTotal += blob.amount

        result = ACCEPTED

    commit()

    // Recalculate ML-based offline limit
    newLimit = computeOfflineLimit(currentUser)
    limitSignature = Ed25519_SIGN(currentUser.id + "|" + newLimit + "|" + expiry)

    return { results, newLimit, limitExpiry, limitSignature }
```

---

## 8. File Inventory — Security Layer

### Flutter (`mobile/lib/services/security/`)
| File | Purpose |
|------|---------|
| `device_key_service.dart` | ECDSA P-256 keypair management, hardware keystore integration, signing/verification |
| `crypto_service.dart` | ECDH key exchange, AES-256-GCM encryption, HKDF derivation, challenge-response |
| `secure_ble_protocol.dart` | Encrypted BLE communication replacing plaintext transfer |
| `device_integrity_service.dart` | Root/jailbreak/emulator detection, kill switch |
| `secure_transaction_engine.dart` | NPCI-compliant limits, nonce tracking, transaction signing |
| `device_registration_service.dart` | Backend device binding via API |
| `security_manager.dart` | Central coordinator, initialization, status queries |

### Backend (`backend/app/`)
| File | Purpose |
|------|---------|
| `models.py` (updated) | Added `DeviceBinding`, `NonceRegistry` models |
| `services/signature_verification.py` | ECDSA P-256 signature verification, nonce uniqueness, timestamp validation |
| `routes/device_routes.py` | Device registration/revocation API |
| `main.py` (updated) | Enhanced `/api/offline/sync` with signature verification, NPCI limits, signed limit responses |

### Database Schema Changes
| Table | Purpose |
|-------|---------|
| `device_bindings` | Maps user → device → ECDSA public key |
| `nonce_registry` | Global nonce dedup for replay prevention |
| `nonce_tracker` (SQLite) | Local nonce dedup on device |
| `device_registry` (SQLite) | Local device key registration log |

---

## 9. Low-End Device Optimizations (Rural Use Case)

| Optimization | Rationale |
|-------------|-----------|
| Integrity check cached for 5 minutes | Avoid repeated file I/O on slow storage |
| ECDH uses P-256 (not P-384/P-521) | Fastest standard curve, still 128-bit security |
| BLE MTU negotiation to 512 bytes | Reduces number of write operations |
| Nonce cleanup runs periodically, not per-txn | Reduces SQLite write amplification |
| Session keys derived with HKDF (no KDF2) | Single-pass derivation, minimal memory |
| AES-256-GCM (not ChaCha20-Poly1305) | Hardware AES-NI on most ARM chips post-2015 |
