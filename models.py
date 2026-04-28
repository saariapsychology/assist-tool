from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    username        = Column(String, primary_key=True, index=True)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, nullable=False)          # "student" | "staff" | "administrator"
    pi_username     = Column(String, ForeignKey("users.username"), nullable=True)

    # Relationships
    sessions        = relationship("ChatSession", back_populates="owner", foreign_keys="ChatSession.owner_username")
    students        = relationship("User", foreign_keys=[pi_username])


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id               = Column(String, primary_key=True, index=True)   # UUID
    owner_username   = Column(String, ForeignKey("users.username"), nullable=False)
    level            = Column(String, nullable=False)
    created_at       = Column(DateTime, default=datetime.utcnow)

    # Relationships
    owner            = relationship("User", back_populates="sessions", foreign_keys=[owner_username])
    messages         = relationship("Message", back_populates="session", order_by="Message.created_at")


class Message(Base):
    __tablename__ = "messages"

    id         = Column(String, primary_key=True, index=True)   # UUID
    session_id = Column(String, ForeignKey("chat_sessions.id"), nullable=False)
    role       = Column(String, nullable=False)                  # "user" | "assistant"
    content    = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    session    = relationship("ChatSession", back_populates="messages")