import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base


class UserRole(str, enum.Enum):
    USER = "user"
    MERCHANT = "merchant"


class TokenStatus(str, enum.Enum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class TransactionStatus(str, enum.Enum):
    PENDING_OFFLINE = "pending_offline"
    SYNCED = "synced"
    SETTLED = "settled"
    FAILED = "failed"
    FRAUD_FLAGGED = "fraud_flagged"


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, nullable=True)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    kyc_tier = Column(Integer, default=1)  # 0-3
    device_trust_score = Column(Float, default=0.5)  # 0.0-1.0
    balance = Column(Float, default=10000.0)  # Starting balance for hackathon demo
    offline_limit = Column(Float, default=0.0)
    offline_limit_used = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    fraud_flags = Column(Integer, default=0)
    transaction_count = Column(Integer, default=0)
    avg_transaction_amount = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tokens = relationship("OfflineToken", back_populates="user")
    sent_transactions = relationship(
        "Transaction", foreign_keys="Transaction.sender_id", back_populates="sender"
    )
    received_transactions = relationship(
        "Transaction", foreign_keys="Transaction.receiver_id", back_populates="receiver"
    )


class OfflineToken(Base):
    __tablename__ = "offline_tokens"

    id = Column(String, primary_key=True, default=generate_uuid)
    token_id = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    nonce = Column(String, unique=True, nullable=False)
    signature = Column(String, nullable=False)
    status = Column(SQLEnum(TokenStatus), default=TokenStatus.ACTIVE)
    consumed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="tokens")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String, primary_key=True, default=generate_uuid)
    token_id = Column(String, index=True, nullable=False)
    sender_id = Column(String, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(String, ForeignKey("users.id"), nullable=True)
    amount = Column(Float, nullable=False)
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING_OFFLINE)
    nonce = Column(String, unique=True, nullable=False)
    device_signature = Column(String, nullable=True)
    merchant_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    synced_at = Column(DateTime, nullable=True)
    settled_at = Column(DateTime, nullable=True)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_transactions")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_transactions")


class DeviceBinding(Base):
    """Binds a user to a specific device via ECDSA P-256 public key."""
    __tablename__ = "device_bindings"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String, unique=True, nullable=False, index=True)
    public_key_pem = Column(String, nullable=False)
    public_key_base64 = Column(String, nullable=False)
    platform = Column(String, nullable=True)  # "android" or "ios"
    os_version = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    integrity_score = Column(Float, default=1.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)


class NonceRegistry(Base):
    """Global nonce registry for replay attack prevention."""
    __tablename__ = "nonce_registry"

    nonce = Column(String, primary_key=True)
    sender_id = Column(String, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class LedgerEntry(Base):
    __tablename__ = "ledger"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    transaction_id = Column(String, ForeignKey("transactions.id"), nullable=False)
    entry_type = Column(String, nullable=False)  # "debit" or "credit"
    amount = Column(Float, nullable=False)
    balance_after = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
