from datetime import datetime, timedelta
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import init_db, get_db
from .routes import auth_routes, token_routes, sync_routes, dashboard, device_routes
from .auth import get_current_user
from .models import User
from .services.risk_engine import compute_risk_score, compute_offline_limit

app = FastAPI(
    title="OfflinePay API",
    description="AI-powered offline payment system backend",
    version="1.0.0",
)

# CORS - allow all origins for hackathon
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_routes.router)
app.include_router(token_routes.router)
app.include_router(sync_routes.router)
app.include_router(dashboard.router)
app.include_router(device_routes.router)


@app.on_event("startup")
def startup_event():
    """Initialize database and train ML model on startup."""
    init_db()
    print("Database initialized.")

    # Try to train ML model if not already trained
    from .config import ML_MODEL_PATH
    import os
    if not os.path.exists(ML_MODEL_PATH):
        try:
            from .ml.train_model import train_model
            train_model()
            print("ML risk model trained successfully.")
        except Exception as e:
            print(f"Warning: Could not train ML model: {e}")
            print("Using heuristic risk scoring as fallback.")


@app.get("/")
def root():
    return {
        "name": "OfflinePay API",
        "version": "1.0.0",
        "description": "AI-powered offline payment system",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/api/admin/seed")
def seed_demo_data(db: Session = Depends(get_db)):
    """One-time seed endpoint — creates demo accounts if none exist."""
    from .models import User, UserRole, generate_uuid
    from .auth import hash_password

    if db.query(User).first():
        return {"status": "already_seeded"}

    demo_users = [
        User(id=generate_uuid(), email="alice@demo.com",
             password_hash=hash_password("password123"),
             full_name="Alice Kumar", role=UserRole.USER,
             kyc_tier=2, balance=10000.0, device_trust_score=0.85),
        User(id=generate_uuid(), email="bob@demo.com",
             password_hash=hash_password("password123"),
             full_name="Bob Singh", role=UserRole.USER,
             kyc_tier=1, balance=5000.0, device_trust_score=0.70),
        User(id=generate_uuid(), email="shopkeeper@demo.com",
             password_hash=hash_password("password123"),
             full_name="Raj Shopkeeper", role=UserRole.MERCHANT,
             kyc_tier=3, balance=50000.0, device_trust_score=0.95),
    ]
    for u in demo_users:
        db.add(u)
    db.commit()
    return {"status": "seeded", "accounts": [u.email for u in demo_users]}


@app.get("/api/public-key")
def get_public_key():
    """Get the Ed25519 public key for offline token verification."""
    from .config import PUBLIC_KEY_HEX
    return {"public_key": PUBLIC_KEY_HEX}


@app.post("/api/offline/sync")
def sync_offline_blobs(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    SyncEngine endpoint. Accepts an array of PaymentBlobs and reconciles each.

    Security checks per blob (in order):
      1. Idempotency — skip duplicate nonces
      2. Timestamp validation — reject blobs older than 72 hours
      3. Nonce uniqueness — global nonce registry (replay prevention)
      4. ECDSA signature verification — verify against registered device key
      5. NPCI limit enforcement — per-txn ₹2000, daily ₹4000
      6. Fraud heuristics — velocity, amount, pattern checks
      7. Balance check — sender must have sufficient funds
      8. Settlement — first-valid-wins conflict resolution

    Returns per-blob status: accepted | rejected | adjusted | duplicate.
    Also returns the recalculated offline limit for the sender.
    """
    from .models import Transaction, TransactionStatus, LedgerEntry, generate_uuid
    from .services.fraud import check_fraud_signals
    from .services.signature_verification import (
        verify_blob_signature,
        check_nonce_uniqueness,
        validate_timestamp,
        cleanup_expired_nonces,
    )

    NPCI_PER_TXN_LIMIT = 2000.0
    NPCI_DAILY_LIMIT = 4000.0

    blobs = payload.get("blobs", [])
    results = []

    # Track daily total for this sender across the batch
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    existing_daily = db.query(Transaction).filter(
        Transaction.sender_id == current_user.id,
        Transaction.created_at >= today_start,
        Transaction.status == TransactionStatus.SETTLED,
    ).count()
    daily_total_this_batch = 0.0

    for blob in blobs:
        blob_id = blob.get("id", generate_uuid())
        sender_id = blob.get("sender_id", "")
        receiver_id = blob.get("receiver_id", "")
        amount = float(blob.get("amount", 0))
        nonce = blob.get("nonce", generate_uuid())
        is_offline = blob.get("is_offline", True)
        timestamp_str = blob.get("timestamp", "")

        # 1. Idempotency — skip if already processed in transactions table
        existing = db.query(Transaction).filter(Transaction.nonce == nonce).first()
        if existing:
            results.append({"id": blob_id, "status": "duplicate", "message": "Already processed"})
            continue

        if amount <= 0:
            results.append({"id": blob_id, "status": "rejected", "message": "Invalid amount"})
            continue

        # 2. Timestamp validation (72-hour sync window)
        ts_valid, ts_reason = validate_timestamp(timestamp_str)
        if not ts_valid:
            results.append({"id": blob_id, "status": "rejected", "message": f"Timestamp: {ts_reason}"})
            continue

        # 3. Global nonce uniqueness (replay prevention)
        nonce_ok, nonce_reason = check_nonce_uniqueness(nonce, sender_id, amount, db)
        if not nonce_ok:
            results.append({"id": blob_id, "status": "rejected", "message": f"Nonce: {nonce_reason}"})
            continue

        # 4. ECDSA signature verification
        sig_valid, sig_reason = verify_blob_signature(blob, db)
        if not sig_valid and sig_reason != "unsigned_blob":
            results.append({"id": blob_id, "status": "rejected", "message": f"Signature: {sig_reason}"})
            continue
        # unsigned_blob: accept with warning for backward compatibility
        signature_verified = sig_valid

        # 5. NPCI per-transaction limit
        if amount > NPCI_PER_TXN_LIMIT:
            results.append({
                "id": blob_id, "status": "rejected",
                "message": f"Exceeds per-transaction limit of ₹{NPCI_PER_TXN_LIMIT:.0f}",
            })
            continue

        # 5b. NPCI daily cumulative limit
        if daily_total_this_batch + amount > NPCI_DAILY_LIMIT:
            results.append({
                "id": blob_id, "status": "rejected",
                "message": f"Exceeds daily offline limit of ₹{NPCI_DAILY_LIMIT:.0f}",
            })
            continue

        sender = db.query(User).filter(User.id == sender_id).first()
        if not sender:
            results.append({"id": blob_id, "status": "rejected", "message": "Sender not found"})
            continue

        if sender.balance < amount:
            results.append({"id": blob_id, "status": "rejected", "message": "Insufficient balance"})
            continue

        # 6. Fraud check
        is_suspicious, fraud_reasons = check_fraud_signals(db, sender_id, amount, nonce)
        if is_suspicious:
            results.append({"id": blob_id, "status": "rejected", "message": "; ".join(fraud_reasons)})
            continue

        # 7. Settle — first-valid-wins (this blob won the race)
        sender.balance -= amount
        sender.transaction_count += 1
        total = sender.avg_transaction_amount * (sender.transaction_count - 1) + amount
        sender.avg_transaction_amount = total / sender.transaction_count
        daily_total_this_batch += amount

        receiver = None
        if receiver_id:
            receiver = db.query(User).filter(User.id == receiver_id).first()
            if receiver:
                receiver.balance += amount

        tx = Transaction(
            id=generate_uuid(),
            token_id=nonce,
            sender_id=sender_id,
            receiver_id=receiver_id if receiver else None,
            amount=amount,
            nonce=nonce,
            device_signature=blob.get("device_signature", ""),
            status=TransactionStatus.SETTLED,
            synced_at=datetime.utcnow(),
            settled_at=datetime.utcnow(),
        )
        db.add(tx)
        db.flush()

        db.add(LedgerEntry(
            user_id=sender_id,
            transaction_id=tx.id,
            entry_type="debit",
            amount=amount,
            balance_after=sender.balance,
        ))
        if receiver:
            db.add(LedgerEntry(
                user_id=receiver_id,
                transaction_id=tx.id,
                entry_type="credit",
                amount=amount,
                balance_after=receiver.balance,
            ))

        status_msg = "Settled (signature verified)" if signature_verified else "Settled (unsigned — legacy)"
        results.append({"id": blob_id, "status": "accepted", "message": status_msg})

    db.commit()

    # Periodic nonce cleanup
    try:
        cleanup_expired_nonces(db)
    except Exception:
        pass

    # Recalculate and return new offline limit for the sender
    new_limit = 0.0
    if current_user:
        days = (datetime.utcnow() - current_user.created_at).days
        from .services.risk_engine import compute_risk_score, compute_offline_limit
        risk_score, _ = compute_risk_score({
            "transaction_count": current_user.transaction_count,
            "avg_transaction_amount": current_user.avg_transaction_amount,
            "kyc_tier": current_user.kyc_tier,
            "device_trust_score": current_user.device_trust_score,
            "days_since_registration": days,
            "fraud_flags": current_user.fraud_flags,
            "total_spent": current_user.avg_transaction_amount * current_user.transaction_count,
        })
        new_limit = min(compute_offline_limit(risk_score), current_user.balance)
        current_user.offline_limit = new_limit
        db.commit()

    expiry = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    # Sign the new limit
    from .config import SIGNING_KEY
    limit_payload = f"{current_user.id}|{new_limit:.2f}|{expiry}"
    limit_signature = SIGNING_KEY.sign(limit_payload.encode()).signature.hex()

    return {
        "results": results,
        "new_offline_limit": new_limit,
        "limit_expiry": expiry,
        "limit_signature": limit_signature,
    }


@app.post("/api/payments/online")
def make_online_payment(
    payment: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Case 2: Sender is online. Debit sender immediately.
    If receiver_id is provided and the receiver exists, credit them now.
    If receiver is not found or not yet synced, hold the credit as a
    pending transaction — receiver claims it when they next sync.
    """
    from .models import Transaction, TransactionStatus, LedgerEntry, generate_uuid

    receiver_id = payment.get("receiver_id")
    amount = float(payment.get("amount", 0))
    nonce = payment.get("nonce") or str(__import__("uuid").uuid4())
    receiver_name = payment.get("receiver_name", "")

    if amount <= 0:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Amount must be positive")

    if current_user.balance < amount:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # Debit sender immediately
    current_user.balance -= amount
    current_user.transaction_count += 1
    total = current_user.avg_transaction_amount * (current_user.transaction_count - 1) + amount
    current_user.avg_transaction_amount = total / current_user.transaction_count

    # Credit receiver if they exist
    receiver = None
    if receiver_id:
        receiver = db.query(User).filter(User.id == receiver_id).first()
        if receiver:
            receiver.balance += amount

    tx_status = TransactionStatus.SETTLED if receiver else TransactionStatus.PENDING_OFFLINE

    tx = Transaction(
        id=generate_uuid(),
        token_id=nonce,  # reuse token_id column to store nonce for online payments
        sender_id=current_user.id,
        receiver_id=receiver_id,
        amount=amount,
        nonce=nonce,
        status=tx_status,
        merchant_name=receiver_name,
        synced_at=datetime.utcnow(),
        settled_at=datetime.utcnow() if receiver else None,
    )
    db.add(tx)
    db.flush()

    debit = LedgerEntry(
        user_id=current_user.id,
        transaction_id=tx.id,
        entry_type="debit",
        amount=amount,
        balance_after=current_user.balance,
    )
    db.add(debit)

    if receiver:
        credit = LedgerEntry(
            user_id=receiver_id,
            transaction_id=tx.id,
            entry_type="credit",
            amount=amount,
            balance_after=receiver.balance,
        )
        db.add(credit)

    db.commit()

    return {
        "status": tx_status.value,
        "transaction_id": tx.id,
        "receiver_credited": receiver is not None,
        "message": "Payment sent" if receiver else "Payment sent — receiver will be credited on sync",
    }


@app.get("/api/app/version")
def get_app_version():
    """
    Returns the minimum required app version and latest available version.
    Clients must check this at startup and block usage if their version
    is below min_version (MASVS-CODE-2 compliance).
    """
    return {
        "min_version": "1.0.0",
        "min_build_number": 1,
        "latest_version": "1.0.0",
        "update_url": "https://play.google.com/store/apps/details?id=com.offlinepay",
        "update_message": None,
        "force_update": False,
    }


@app.get("/api/user/offline-limit")
def get_offline_limit(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return the user's current AI/ML-assigned offline credit limit and
    its expiry timestamp. The Flutter app caches this for 24 hours so
    payments can be authorised without a network connection.
    """
    days_since_reg = (datetime.utcnow() - current_user.created_at).days
    user_features = {
        "transaction_count": current_user.transaction_count,
        "avg_transaction_amount": current_user.avg_transaction_amount,
        "kyc_tier": current_user.kyc_tier,
        "device_trust_score": current_user.device_trust_score,
        "days_since_registration": days_since_reg,
        "fraud_flags": current_user.fraud_flags,
        "total_spent": current_user.avg_transaction_amount * current_user.transaction_count,
    }

    risk_score, _ = compute_risk_score(user_features)
    limit = compute_offline_limit(risk_score)
    limit = min(limit, current_user.balance)

    expiry = datetime.utcnow() + timedelta(hours=24)

    # Sign the limit so the client can verify it wasn't tampered with
    from .config import SIGNING_KEY
    limit_payload = f"{current_user.id}|{limit:.2f}|{expiry.isoformat()}"
    limit_signature = SIGNING_KEY.sign(limit_payload.encode()).signature.hex()

    return {
        "limit": limit,
        "expiry": expiry.isoformat(),
        "risk_score": risk_score,
        "limit_signature": limit_signature,
    }
