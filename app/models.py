from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    repository_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_code: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scans: Mapped[list["ScanTask"]] = relationship(back_populates="project", cascade="all, delete-orphan")

class ScanTask(Base):
    __tablename__ = "scan_tasks"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), default="completed", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    gate_decision: Mapped["GateDecision | None"] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")
    reports: Mapped[list["ReportArtifact"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(300), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    code_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    scan: Mapped[ScanTask] = relationship(back_populates="findings")

class GateDecision(Base):
    __tablename__ = "gate_decisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), unique=True, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    max_critical: Mapped[int] = mapped_column(Integer, default=0)
    max_high: Mapped[int] = mapped_column(Integer, default=0)
    scan: Mapped[ScanTask] = relationship(back_populates="gate_decision")

class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scan: Mapped[ScanTask] = relationship(back_populates="reports")

Index("ix_findings_scan_severity", Finding.scan_id, Finding.severity)



class ThresholdConfig(Base):
    __tablename__ = "threshold_configs"
    id: Mapped[int] = mapped_column(primary_key=True)
    max_critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
