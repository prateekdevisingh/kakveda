from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


DB_URL = os.environ.get("DASHBOARD_DB_URL", "sqlite:////app/data/dashboard.db")

engine = create_engine(DB_URL, future=True, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    roles: Mapped[list[UserRole]] = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")


class Project(Base):
    """Workspace/project boundary (project/team scope).

    Runs and related artifacts can be scoped to a project for isolation and budgets.
    """

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class ProjectMember(Base):
    """User -> project mapping with a coarse role (owner|member|viewer)."""

    __tablename__ = "project_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(32), default="member")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ProjectApiKey(Base):
    """Simple API key for ingest/write operations scoped to a project."""

    __tablename__ = "project_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="default")
    # Store hashed key only (demo-grade). The raw token is only shown once at creation.
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProjectBudget(Base):
    """Budget per project/provider (optional), in USD for a rolling period."""

    __tablename__ = "project_budgets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    provider: Mapped[str] = mapped_column(String(64), default="ollama")
    monthly_usd: Mapped[float] = mapped_column(Integer, default=0)  # stored as cents-like int for SQLite simplicity
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class InfraDashboardLayout(Base):
    """Saved infra dashboard layout/threshold/filter config per user/project."""

    __tablename__ = "infra_dashboard_layouts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user_email: Mapped[str] = mapped_column(String(320), index=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True, index=True)
    layout_uid: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class NetraAgentConfig(Base):
    """Dashboard-controlled runtime config for kakveda-netra agents."""

    __tablename__ = "netra_agent_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    agent_name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    config_json: Mapped[str] = mapped_column(Text, default="{}")


class TracePipelineConfig(Base):
    """Global/tenant-level trace pipeline controls."""

    __tablename__ = "trace_pipeline_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, default="default")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=14)
    default_sample_rate: Mapped[int] = mapped_column(Integer, default=100)  # 0..100
    keep_error_traces: Mapped[bool] = mapped_column(Boolean, default=True)
    drop_healthcheck_traces: Mapped[bool] = mapped_column(Boolean, default=True)


class ProjectRetentionPolicy(Base):
    """Per-project retention/cap overrides for ingest housekeeping."""

    __tablename__ = "project_retention_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    trace_retention_days: Mapped[int] = mapped_column(Integer, default=30)
    trace_max_rows: Mapped[int] = mapped_column(Integer, default=250000)
    infra_retention_days: Mapped[int] = mapped_column(Integer, default=14)
    infra_max_rows: Mapped[int] = mapped_column(Integer, default=120000)
    observability_retention_days: Mapped[int] = mapped_column(Integer, default=14)
    observability_max_rows: Mapped[int] = mapped_column(Integer, default=120000)


class TraceSamplingRule(Base):
    """Sampling override rules evaluated by priority."""

    __tablename__ = "trace_sampling_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    name: Mapped[str] = mapped_column(String(128), default="rule")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)

    app_id_pattern: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name_pattern: Mapped[str | None] = mapped_column(String(128), nullable=True)
    min_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_only: Mapped[bool] = mapped_column(Boolean, default=False)
    sample_rate: Mapped[int] = mapped_column(Integer, default=100)  # 0..100


class SpanMetricConfig(Base):
    """Config describing derived metrics from spans."""

    __tablename__ = "span_metric_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    span_name_pattern: Mapped[str] = mapped_column(String(128), default="*")
    app_id_pattern: Mapped[str | None] = mapped_column(String(128), nullable=True)
    aggregation: Mapped[str] = mapped_column(String(16), default="count")  # count|avg|max|p95
    field_name: Mapped[str] = mapped_column(String(32), default="duration_ms")


class SpanMetricPoint(Base):
    """Persisted points generated from span metric configs."""

    __tablename__ = "span_metric_points"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    metric_name: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_run_id: Mapped[int | None] = mapped_column(ForeignKey("trace_runs.id"), nullable=True, index=True)
    value: Mapped[float] = mapped_column(Float, default=0.0)


class APMErrorGroup(Base):
    """Grouped backend exceptions for APM error tracking workflows."""

    __tablename__ = "apm_error_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    first_seen_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    signature: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    error_type: Mapped[str] = mapped_column(String(128), default="error", index=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    environment: Mapped[str] = mapped_column(String(64), default="default", index=True)
    handled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    workflow_status: Mapped[str] = mapped_column(String(32), default="open", index=True)  # open|ack|resolved|ignored
    assignee: Mapped[str | None] = mapped_column(String(320), nullable=True)
    workflow_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class APMErrorEvent(Base):
    """Individual error occurrence linked to a grouped signature."""

    __tablename__ = "apm_error_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    error_group_id: Mapped[int] = mapped_column(ForeignKey("apm_error_groups.id"), index=True)
    trace_run_id: Mapped[int | None] = mapped_column(ForeignKey("trace_runs.id"), nullable=True, index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    environment: Mapped[str] = mapped_column(String(64), default="default", index=True)
    handled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    error_type: Mapped[str] = mapped_column(String(128), default="error", index=True)
    error_message: Mapped[str] = mapped_column(Text, default="")
    stack_trace: Mapped[str | None] = mapped_column(Text, nullable=True)
    replay_context_json: Mapped[str] = mapped_column(Text, default="{}")


class ProfilerSample(Base):
    """Continuous profiler sample (method/span hotspots over time)."""

    __tablename__ = "profiler_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    environment: Mapped[str] = mapped_column(String(64), default="default", index=True)
    service_name: Mapped[str] = mapped_column(String(128), index=True)
    method_name: Mapped[str] = mapped_column(String(256), index=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    trace_run_id: Mapped[int | None] = mapped_column(ForeignKey("trace_runs.id"), nullable=True, index=True)
    sample_type: Mapped[str] = mapped_column(String(32), default="cpu", index=True)  # cpu|memory
    cpu_ms: Mapped[float] = mapped_column(Float, default=0.0)
    memory_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sample_count: Mapped[int] = mapped_column(Integer, default=1)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class DynamicInstrumentationRule(Base):
    """Runtime instrumentation control (without agent restart)."""

    __tablename__ = "dynamic_instrumentation_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    scope_type: Mapped[str] = mapped_column(String(16), default="agent", index=True)  # agent|app|global
    scope_value: Mapped[str] = mapped_column(String(128), default="*", index=True)
    rule_type: Mapped[str] = mapped_column(String(16), default="log", index=True)  # log|metric|span
    target_pattern: Mapped[str] = mapped_column(String(256), default="*")
    condition_expr: Mapped[str | None] = mapped_column(Text, nullable=True)
    action_json: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class DynamicInstrumentationFeedback(Base):
    """Execution feedback from agents for runtime instrumentation rules."""

    __tablename__ = "dynamic_instrumentation_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    agent_name: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("dynamic_instrumentation_rules.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="applied", index=True)  # applied|failed|skipped
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class DBQuerySample(Base):
    """Database monitoring sample/event."""

    __tablename__ = "db_query_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    app_id: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    agent_id: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    environment: Mapped[str] = mapped_column(String(64), default="default", index=True)
    db_system: Mapped[str] = mapped_column(String(32), default="unknown", index=True)  # postgres|mysql|sqlite|...
    db_instance: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    query_fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    query_text: Mapped[str] = mapped_column(Text, default="")
    query_type: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    rows_examined: Mapped[int] = mapped_column(Integer, default=0)
    rows_returned: Mapped[int] = mapped_column(Integer, default=0)
    wait_event: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    explain_plan_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta_json: Mapped[str] = mapped_column(Text, default="{}")


class RUMEvent(Base):
    """Real User Monitoring event from web/mobile clients."""

    __tablename__ = "rum_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    app_id: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    environment: Mapped[str] = mapped_column(String(64), default="default", index=True)
    platform: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # web|ios|android
    device_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    user_id_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    page: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    action: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    load_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    lcp_ms: Mapped[float] = mapped_column(Float, default=0.0)
    fid_ms: Mapped[float] = mapped_column(Float, default=0.0)
    cls: Mapped[float] = mapped_column(Float, default=0.0)
    js_error_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    js_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    release_version: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    meta_json: Mapped[str] = mapped_column(Text, default="{}")


class RUMMonitor(Base):
    """RUM threshold monitor configuration."""

    __tablename__ = "rum_monitors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    app_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    metric_name: Mapped[str] = mapped_column(String(64), default="lcp_ms", index=True)
    threshold_value: Mapped[float] = mapped_column(Float, default=2500.0)
    threshold_op: Mapped[str] = mapped_column(String(8), default=">", index=True)  # >|<|>=|<=
    window_minutes: Mapped[int] = mapped_column(Integer, default=15)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class APMMonitor(Base):
    """APM metric/trace/anomaly monitor configuration."""

    __tablename__ = "apm_monitors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    app_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    monitor_type: Mapped[str] = mapped_column(String(32), default="metric", index=True)  # metric|trace|anomaly
    metric_name: Mapped[str] = mapped_column(String(64), default="error_rate_percent", index=True)
    threshold_value: Mapped[float] = mapped_column(Float, default=5.0)
    threshold_op: Mapped[str] = mapped_column(String(8), default=">", index=True)
    window_minutes: Mapped[int] = mapped_column(Integer, default=15)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    auto_generated: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class MonitorAlert(Base):
    """Triggered alert from RUM/APM monitors."""

    __tablename__ = "monitor_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source_type: Mapped[str] = mapped_column(String(16), default="apm", index=True)  # apm|rum
    monitor_id: Mapped[int] = mapped_column(Integer, index=True)
    monitor_name: Mapped[str] = mapped_column(String(128), index=True)
    app_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="warning", index=True)  # info|warning|critical
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|resolved
    metric_name: Mapped[str] = mapped_column(String(64), default="metric", index=True)
    observed_value: Mapped[float] = mapped_column(Float, default=0.0)
    threshold_value: Mapped[float] = mapped_column(Float, default=0.0)
    context_json: Mapped[str] = mapped_column(Text, default="{}")


class AgentRegistry(Base):
    """Registered external/internal agents (MLflow/LangSmith-like registry).

    Self-hosted mode: single tenant.
    Admin-only: only admins can register/enable/disable.
    """

    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    base_url: Mapped[str] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # JSON-encoded arrays to keep SQLite-simple.
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    events_in_json: Mapped[str] = mapped_column(Text, default="[]")
    events_out_json: Mapped[str] = mapped_column(Text, default="[]")

    # Auth configuration (token itself should be stored/managed via env/secret stores).
    auth_type: Mapped[str] = mapped_column(String(32), default="none")  # none|bearer|api_key_header
    auth_header_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_secret_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)


class UserRole(Base):
    __tablename__ = "user_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), index=True)

    user: Mapped[User] = relationship("User", back_populates="roles")
    role: Mapped[Role] = relationship("Role")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(Text)


class Scenario(Base):
    """Predefined test scenarios for dashboard testing and demos."""
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # Q1, Q2, ..., Q50
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    expected_behavior: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64))  # Preflight Validation, GFKB & Pattern Matching, etc.
    difficulty: Mapped[str] = mapped_column(String(32))  # Easy, Medium, Hard, Expert
    default_prompt: Mapped[str] = mapped_column(Text)


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    prompt: Mapped[str] = mapped_column(Text)
    scenario_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("scenarios.id"), nullable=True)
    scenario_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    expected_behavior: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class WarningEvent(Base):
    __tablename__ = "warning_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))
    pattern_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str] = mapped_column(Text)
    references_json: Mapped[str] = mapped_column(Text, default="[]")


class TraceRun(Base):
    """A single runnable invocation with inputs/outputs and timing."""

    __tablename__ = "trace_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    # correlate to UI-driven scenario (optional)
    scenario_run_id: Mapped[int | None] = mapped_column(ForeignKey("scenario_runs.id"), index=True, nullable=True)

    # Project boundary (optional for backwards compatibility)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), index=True, nullable=True)

    app_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)

    # Structured metadata extracted from output_json.gen for fast filtering.
    provider: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)

    name: Mapped[str] = mapped_column(String(128), default="agent.run")
    status: Mapped[str] = mapped_column(String(32), default="completed")  # completed|error

    input_json: Mapped[str] = mapped_column(Text, default="{}")
    output_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Token / cost tracking
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Integer, nullable=True)  # stored as micro-dollars (int) for SQLite


class PromptLibrary(Base):
    """Prompt artifact container."""

    __tablename__ = "prompt_library"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class PromptVersion(Base):
    """Versioned prompt text + default model/provider hints."""

    __tablename__ = "prompt_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    prompt_id: Mapped[int] = mapped_column(ForeignKey("prompt_library.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, index=True)

    prompt_text: Mapped[str] = mapped_column(Text)
    default_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    default_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)

    tags_json: Mapped[str] = mapped_column(Text, default="[]")


class Experiment(Base):
    """Experiment container used to group repeated runs."""

    __tablename__ = "experiments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class ExperimentRun(Base):
    """Connect a TraceRun to an Experiment (many runs per experiment)."""

    __tablename__ = "experiment_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    experiment_id: Mapped[int] = mapped_column(ForeignKey("experiments.id"), index=True)
    trace_run_id: Mapped[int] = mapped_column(ForeignKey("trace_runs.id"), index=True)

    # Optional metadata (e.g., which prompt version produced this run)
    prompt_version_id: Mapped[int | None] = mapped_column(ForeignKey("prompt_versions.id"), index=True, nullable=True)
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Dataset(Base):
    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class DatasetExample(Base):
    __tablename__ = "dataset_examples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), index=True)

    # Store minimal prompt/example data
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    input_json: Mapped[str] = mapped_column(Text, default="{}")
    expected_output_json: Mapped[str] = mapped_column(Text, default="{}")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")

    # Optional quick-preview fields when running an example directly from the dataset page.
    last_run_output_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_run_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_run_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)


class RunFeedback(Base):
    """Tiny feedback primitive (ratings/tags/annotations)."""

    __tablename__ = "run_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    trace_run_id: Mapped[int] = mapped_column(ForeignKey("trace_runs.id"), index=True)
    key: Mapped[str] = mapped_column(String(64))  # e.g. 'rating', 'tag', 'note'
    value: Mapped[str] = mapped_column(Text)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)


class TraceSpan(Base):
    """Nested spans inside a TraceRun for timeline visualization."""

    __tablename__ = "trace_spans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trace_run_id: Mapped[int] = mapped_column(ForeignKey("trace_runs.id"), index=True)

    parent_id: Mapped[int | None] = mapped_column(ForeignKey("trace_spans.id"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(128))
    start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    end_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    meta_json: Mapped[str] = mapped_column(Text, default="{}")


class EvaluationRun(Base):
    """Dataset-based evaluation run."""

    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="eval")

    summary_json: Mapped[str] = mapped_column(Text, default="{}")


class EvaluationResult(Base):
    __tablename__ = "evaluation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    eval_run_id: Mapped[int] = mapped_column(ForeignKey("evaluation_runs.id"), index=True)
    dataset_example_id: Mapped[int] = mapped_column(ForeignKey("dataset_examples.id"), index=True)

    trace_run_id: Mapped[int | None] = mapped_column(ForeignKey("trace_runs.id"), index=True, nullable=True)

    score: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    details_json: Mapped[str] = mapped_column(Text, default="{}")


def init_db() -> None:
    Base.metadata.create_all(engine)


def migrate_db() -> None:
    """Best-effort SQLite migrations for demo portability.

    This project favors a single-file SQLite DB for the dashboard. For the demo,
    we keep migrations lightweight by `ALTER TABLE ADD COLUMN` when missing.
    Safe to run on every startup.
    """
    if not DB_URL.startswith("sqlite:"):
        return

    # DB_URL looks like: sqlite:////app/data/dashboard.db
    db_path = DB_URL.replace("sqlite:////", "/")
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()

        def cols(table: str) -> set[str]:
            return {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}

        # warning_events.prompt
        if "warning_events" in {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}:
            c = cols("warning_events")
            if "prompt" not in c:
                cur.execute("ALTER TABLE warning_events ADD COLUMN prompt TEXT")

        # trace_runs.provider/model for fast filtering
        if "trace_runs" in {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}:
            c = cols("trace_runs")
            if "provider" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN provider TEXT")
            if "model" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN model TEXT")

            # project + cost tracking (best-effort)
            if "project_id" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN project_id INTEGER")
            if "prompt_tokens" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN prompt_tokens INTEGER")
            if "completion_tokens" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN completion_tokens INTEGER")
            if "total_tokens" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN total_tokens INTEGER")
            if "cost_usd" not in c:
                cur.execute("ALTER TABLE trace_runs ADD COLUMN cost_usd INTEGER")

            # best-effort indexes (ignore if already there)
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_runs_provider ON trace_runs(provider)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_runs_model ON trace_runs(model)")
            except Exception:
                pass

            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_runs_project_id ON trace_runs(project_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_runs_total_tokens ON trace_runs(total_tokens)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_runs_cost_usd ON trace_runs(cost_usd)")
            except Exception:
                pass

    # Prompt library + prompt versions
        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

        # Agent registry (admin-only feature)
        if "agents" not in tables:
            cur.execute(
                """
                CREATE TABLE agents (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    description TEXT,
                    base_url VARCHAR(512),
                    enabled BOOLEAN,
                    capabilities_json TEXT,
                    events_in_json TEXT,
                    events_out_json TEXT,
                    auth_type VARCHAR(32),
                    auth_header_name VARCHAR(64),
                    auth_secret_ref VARCHAR(128)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_agents_name ON agents(name)")
            except Exception:
                pass

        # Projects + API keys + budgets
        if "projects" not in tables:
            cur.execute(
                """
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    description TEXT
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_projects_name ON projects(name)")
            except Exception:
                pass

        if "project_members" not in tables:
            cur.execute(
                """
                CREATE TABLE project_members (
                    id INTEGER PRIMARY KEY,
                    project_id INTEGER,
                    user_id INTEGER,
                    role VARCHAR(32),
                    created_at DATETIME,
                    FOREIGN KEY(project_id) REFERENCES projects(id),
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_project_members_project_id ON project_members(project_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_project_members_user_id ON project_members(user_id)")
            except Exception:
                pass

        if "project_api_keys" not in tables:
            cur.execute(
                """
                CREATE TABLE project_api_keys (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    project_id INTEGER,
                    name VARCHAR(128),
                    key_hash VARCHAR(128) UNIQUE,
                    is_active BOOLEAN,
                    last_used_at DATETIME,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_project_api_keys_key_hash ON project_api_keys(key_hash)")
            except Exception:
                pass

        if "project_budgets" not in tables:
            cur.execute(
                """
                CREATE TABLE project_budgets (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    project_id INTEGER,
                    provider VARCHAR(64),
                    monthly_usd INTEGER,
                    enabled BOOLEAN,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_project_budgets_project_id ON project_budgets(project_id)")
            except Exception:
                pass

        if "infra_dashboard_layouts" not in tables:
            cur.execute(
                """
                CREATE TABLE infra_dashboard_layouts (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    user_email VARCHAR(320),
                    project_id INTEGER,
                    layout_uid VARCHAR(64),
                    name VARCHAR(128),
                    config_json TEXT,
                    is_default BOOLEAN,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_infra_layout_user_email ON infra_dashboard_layouts(user_email)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_infra_layout_project_id ON infra_dashboard_layouts(project_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_infra_layout_uid ON infra_dashboard_layouts(layout_uid)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_infra_layout_is_default ON infra_dashboard_layouts(is_default)")
            except Exception:
                pass
        else:
            c = cols("infra_dashboard_layouts")
            if "updated_at" not in c:
                cur.execute("ALTER TABLE infra_dashboard_layouts ADD COLUMN updated_at DATETIME")
            if "is_default" not in c:
                cur.execute("ALTER TABLE infra_dashboard_layouts ADD COLUMN is_default BOOLEAN")
            if "layout_uid" not in c:
                cur.execute("ALTER TABLE infra_dashboard_layouts ADD COLUMN layout_uid VARCHAR(64)")
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_infra_layout_uid ON infra_dashboard_layouts(layout_uid)")
            except Exception:
                pass

        if "netra_agent_configs" not in tables:
            cur.execute(
                """
                CREATE TABLE netra_agent_configs (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    agent_name VARCHAR(128) UNIQUE,
                    config_json TEXT
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_netra_agent_configs_agent_name ON netra_agent_configs(agent_name)")
            except Exception:
                pass
        if "prompt_library" not in tables:
            cur.execute(
                """
                CREATE TABLE prompt_library (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    description TEXT
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_prompt_library_name ON prompt_library(name)")
            except Exception:
                pass

        if "prompt_versions" not in tables:
            cur.execute(
                """
                CREATE TABLE prompt_versions (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    prompt_id INTEGER,
                    version INTEGER,
                    prompt_text TEXT,
                    default_model VARCHAR(128),
                    default_provider VARCHAR(64),
                    tags_json TEXT,
                    FOREIGN KEY(prompt_id) REFERENCES prompt_library(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_prompt_versions_prompt_id ON prompt_versions(prompt_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_prompt_versions_version ON prompt_versions(version)")
            except Exception:
                pass

    # Experiments + experiment runs
        if "experiments" not in tables:
            cur.execute(
                """
                CREATE TABLE experiments (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    description TEXT
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_experiments_name ON experiments(name)")
            except Exception:
                pass

        if "experiment_runs" not in tables:
            cur.execute(
                """
                CREATE TABLE experiment_runs (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    experiment_id INTEGER,
                    trace_run_id INTEGER,
                    prompt_version_id INTEGER,
                    label VARCHAR(128),
                    FOREIGN KEY(experiment_id) REFERENCES experiments(id),
                    FOREIGN KEY(trace_run_id) REFERENCES trace_runs(id),
                    FOREIGN KEY(prompt_version_id) REFERENCES prompt_versions(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_experiment_runs_experiment_id ON experiment_runs(experiment_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_experiment_runs_trace_run_id ON experiment_runs(trace_run_id)")
            except Exception:
                pass

        # dataset_examples quick-preview fields
        if "dataset_examples" in {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}:
            c = cols("dataset_examples")
            if "last_run_output_json" not in c:
                cur.execute("ALTER TABLE dataset_examples ADD COLUMN last_run_output_json TEXT")
            if "last_run_latency_ms" not in c:
                cur.execute("ALTER TABLE dataset_examples ADD COLUMN last_run_latency_ms INTEGER")
            if "last_run_provider" not in c:
                cur.execute("ALTER TABLE dataset_examples ADD COLUMN last_run_provider TEXT")

        # scenarios + scenario_runs (ensure new columns exist for /scenarios UI)
        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "scenarios" not in tables:
            cur.execute(
                """
                CREATE TABLE scenarios (
                    id INTEGER PRIMARY KEY,
                    code VARCHAR(16) UNIQUE,
                    title VARCHAR(256),
                    description TEXT,
                    expected_behavior TEXT,
                    category VARCHAR(64),
                    difficulty VARCHAR(32),
                    default_prompt TEXT
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_scenarios_code ON scenarios(code)")
            except Exception:
                pass

        if "scenario_runs" not in tables:
            cur.execute(
                """
                CREATE TABLE scenario_runs (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    app_id VARCHAR(64),
                    agent_id VARCHAR(64),
                    prompt TEXT,
                    scenario_id INTEGER,
                    scenario_code VARCHAR(16),
                    expected_behavior TEXT,
                    note TEXT,
                    FOREIGN KEY(scenario_id) REFERENCES scenarios(id)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_scenario_runs_ts ON scenario_runs(ts)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_scenario_runs_app_id ON scenario_runs(app_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_scenario_runs_agent_id ON scenario_runs(agent_id)")
            except Exception:
                pass
        else:
            c = cols("scenario_runs")
            if "scenario_id" not in c:
                cur.execute("ALTER TABLE scenario_runs ADD COLUMN scenario_id INTEGER")
            if "scenario_code" not in c:
                cur.execute("ALTER TABLE scenario_runs ADD COLUMN scenario_code VARCHAR(16)")
            if "expected_behavior" not in c:
                cur.execute("ALTER TABLE scenario_runs ADD COLUMN expected_behavior TEXT")
            if "note" not in c:
                cur.execute("ALTER TABLE scenario_runs ADD COLUMN note TEXT")

        # Trace pipeline controls + derived span metrics
        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "trace_pipeline_configs" not in tables:
            cur.execute(
                """
                CREATE TABLE trace_pipeline_configs (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    name VARCHAR(64) UNIQUE,
                    enabled BOOLEAN,
                    retention_days INTEGER,
                    default_sample_rate INTEGER,
                    keep_error_traces BOOLEAN,
                    drop_healthcheck_traces BOOLEAN
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_pipeline_configs_name ON trace_pipeline_configs(name)")
            except Exception:
                pass
            cur.execute(
                """
                INSERT INTO trace_pipeline_configs
                (created_at, updated_at, name, enabled, retention_days, default_sample_rate, keep_error_traces, drop_healthcheck_traces)
                VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'default', 1, 14, 100, 1, 1)
                """
            )

        if "project_retention_policies" not in tables:
            cur.execute(
                """
                CREATE TABLE project_retention_policies (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    project_id INTEGER,
                    enabled BOOLEAN,
                    trace_retention_days INTEGER,
                    trace_max_rows INTEGER,
                    infra_retention_days INTEGER,
                    infra_max_rows INTEGER,
                    observability_retention_days INTEGER,
                    observability_max_rows INTEGER,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_project_retention_policies_project_id ON project_retention_policies(project_id)",
                "CREATE INDEX IF NOT EXISTS ix_project_retention_policies_enabled ON project_retention_policies(enabled)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "trace_sampling_rules" not in tables:
            cur.execute(
                """
                CREATE TABLE trace_sampling_rules (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    name VARCHAR(128),
                    enabled BOOLEAN,
                    priority INTEGER,
                    app_id_pattern VARCHAR(128),
                    name_pattern VARCHAR(128),
                    min_duration_ms INTEGER,
                    error_only BOOLEAN,
                    sample_rate INTEGER
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_sampling_rules_priority ON trace_sampling_rules(priority)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_trace_sampling_rules_enabled ON trace_sampling_rules(enabled)")
            except Exception:
                pass

        if "span_metric_configs" not in tables:
            cur.execute(
                """
                CREATE TABLE span_metric_configs (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    enabled BOOLEAN,
                    span_name_pattern VARCHAR(128),
                    app_id_pattern VARCHAR(128),
                    aggregation VARCHAR(16),
                    field_name VARCHAR(32)
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_span_metric_configs_name ON span_metric_configs(name)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_span_metric_configs_enabled ON span_metric_configs(enabled)")
            except Exception:
                pass

        if "span_metric_points" not in tables:
            cur.execute(
                """
                CREATE TABLE span_metric_points (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    metric_name VARCHAR(128),
                    app_id VARCHAR(64),
                    trace_run_id INTEGER,
                    value FLOAT
                )
                """
            )
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_span_metric_points_metric_name ON span_metric_points(metric_name)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_span_metric_points_app_id ON span_metric_points(app_id)")
            except Exception:
                pass
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS ix_span_metric_points_ts ON span_metric_points(ts)")
            except Exception:
                pass

        if "apm_error_groups" not in tables:
            cur.execute(
                """
                CREATE TABLE apm_error_groups (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    first_seen_ts DATETIME,
                    last_seen_ts DATETIME,
                    signature VARCHAR(128) UNIQUE,
                    error_type VARCHAR(128),
                    error_message TEXT,
                    service_name VARCHAR(128),
                    app_id VARCHAR(64),
                    environment VARCHAR(64),
                    handled BOOLEAN,
                    occurrence_count INTEGER,
                    workflow_status VARCHAR(32),
                    assignee VARCHAR(320),
                    workflow_notes TEXT
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_apm_error_groups_signature ON apm_error_groups(signature)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_groups_app_id ON apm_error_groups(app_id)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_groups_environment ON apm_error_groups(environment)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_groups_workflow_status ON apm_error_groups(workflow_status)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_groups_last_seen_ts ON apm_error_groups(last_seen_ts)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "apm_error_events" not in tables:
            cur.execute(
                """
                CREATE TABLE apm_error_events (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    ts DATETIME,
                    error_group_id INTEGER,
                    trace_run_id INTEGER,
                    app_id VARCHAR(64),
                    agent_id VARCHAR(64),
                    service_name VARCHAR(128),
                    environment VARCHAR(64),
                    handled BOOLEAN,
                    error_type VARCHAR(128),
                    error_message TEXT,
                    stack_trace TEXT,
                    replay_context_json TEXT,
                    FOREIGN KEY(error_group_id) REFERENCES apm_error_groups(id),
                    FOREIGN KEY(trace_run_id) REFERENCES trace_runs(id)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_apm_error_events_error_group_id ON apm_error_events(error_group_id)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_events_trace_run_id ON apm_error_events(trace_run_id)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_events_app_id ON apm_error_events(app_id)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_events_environment ON apm_error_events(environment)",
                "CREATE INDEX IF NOT EXISTS ix_apm_error_events_ts ON apm_error_events(ts)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "profiler_samples" not in tables:
            cur.execute(
                """
                CREATE TABLE profiler_samples (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    app_id VARCHAR(64),
                    agent_id VARCHAR(64),
                    environment VARCHAR(64),
                    service_name VARCHAR(128),
                    method_name VARCHAR(256),
                    version VARCHAR(64),
                    trace_run_id INTEGER,
                    sample_type VARCHAR(32),
                    cpu_ms FLOAT,
                    memory_bytes INTEGER,
                    sample_count INTEGER,
                    details_json TEXT,
                    FOREIGN KEY(trace_run_id) REFERENCES trace_runs(id)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_profiler_samples_ts ON profiler_samples(ts)",
                "CREATE INDEX IF NOT EXISTS ix_profiler_samples_app_id ON profiler_samples(app_id)",
                "CREATE INDEX IF NOT EXISTS ix_profiler_samples_environment ON profiler_samples(environment)",
                "CREATE INDEX IF NOT EXISTS ix_profiler_samples_method_name ON profiler_samples(method_name)",
                "CREATE INDEX IF NOT EXISTS ix_profiler_samples_trace_run_id ON profiler_samples(trace_run_id)",
                "CREATE INDEX IF NOT EXISTS ix_profiler_samples_version ON profiler_samples(version)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "dynamic_instrumentation_rules" not in tables:
            cur.execute(
                """
                CREATE TABLE dynamic_instrumentation_rules (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    scope_type VARCHAR(16),
                    scope_value VARCHAR(128),
                    rule_type VARCHAR(16),
                    target_pattern VARCHAR(256),
                    condition_expr TEXT,
                    action_json TEXT,
                    enabled BOOLEAN,
                    created_by VARCHAR(320)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_dyn_instr_scope_type ON dynamic_instrumentation_rules(scope_type)",
                "CREATE INDEX IF NOT EXISTS ix_dyn_instr_scope_value ON dynamic_instrumentation_rules(scope_value)",
                "CREATE INDEX IF NOT EXISTS ix_dyn_instr_rule_type ON dynamic_instrumentation_rules(rule_type)",
                "CREATE INDEX IF NOT EXISTS ix_dyn_instr_enabled ON dynamic_instrumentation_rules(enabled)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "dynamic_instrumentation_feedback" not in tables:
            cur.execute(
                """
                CREATE TABLE dynamic_instrumentation_feedback (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    agent_name VARCHAR(128),
                    app_id VARCHAR(64),
                    rule_id INTEGER,
                    status VARCHAR(32),
                    message TEXT,
                    details_json TEXT,
                    FOREIGN KEY(rule_id) REFERENCES dynamic_instrumentation_rules(id)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_dyn_feedback_ts ON dynamic_instrumentation_feedback(ts)",
                "CREATE INDEX IF NOT EXISTS ix_dyn_feedback_agent_name ON dynamic_instrumentation_feedback(agent_name)",
                "CREATE INDEX IF NOT EXISTS ix_dyn_feedback_rule_id ON dynamic_instrumentation_feedback(rule_id)",
                "CREATE INDEX IF NOT EXISTS ix_dyn_feedback_status ON dynamic_instrumentation_feedback(status)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "db_query_samples" not in tables:
            cur.execute(
                """
                CREATE TABLE db_query_samples (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    app_id VARCHAR(64),
                    agent_id VARCHAR(64),
                    environment VARCHAR(64),
                    db_system VARCHAR(32),
                    db_instance VARCHAR(128),
                    service_name VARCHAR(128),
                    query_fingerprint VARCHAR(128),
                    query_text TEXT,
                    query_type VARCHAR(16),
                    duration_ms FLOAT,
                    rows_examined INTEGER,
                    rows_returned INTEGER,
                    wait_event VARCHAR(128),
                    explain_plan_json TEXT,
                    meta_json TEXT
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_db_query_samples_ts ON db_query_samples(ts)",
                "CREATE INDEX IF NOT EXISTS ix_db_query_samples_app_id ON db_query_samples(app_id)",
                "CREATE INDEX IF NOT EXISTS ix_db_query_samples_environment ON db_query_samples(environment)",
                "CREATE INDEX IF NOT EXISTS ix_db_query_samples_fingerprint ON db_query_samples(query_fingerprint)",
                "CREATE INDEX IF NOT EXISTS ix_db_query_samples_duration_ms ON db_query_samples(duration_ms)",
                "CREATE INDEX IF NOT EXISTS ix_db_query_samples_query_type ON db_query_samples(query_type)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "rum_events" not in tables:
            cur.execute(
                """
                CREATE TABLE rum_events (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    app_id VARCHAR(64),
                    agent_id VARCHAR(64),
                    environment VARCHAR(64),
                    platform VARCHAR(32),
                    device_type VARCHAR(32),
                    session_id VARCHAR(128),
                    user_id_hash VARCHAR(128),
                    page VARCHAR(256),
                    action VARCHAR(128),
                    load_time_ms FLOAT,
                    lcp_ms FLOAT,
                    fid_ms FLOAT,
                    cls FLOAT,
                    js_error_name VARCHAR(128),
                    js_error_message TEXT,
                    release_version VARCHAR(64),
                    meta_json TEXT
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_rum_events_ts ON rum_events(ts)",
                "CREATE INDEX IF NOT EXISTS ix_rum_events_app_id ON rum_events(app_id)",
                "CREATE INDEX IF NOT EXISTS ix_rum_events_environment ON rum_events(environment)",
                "CREATE INDEX IF NOT EXISTS ix_rum_events_session_id ON rum_events(session_id)",
                "CREATE INDEX IF NOT EXISTS ix_rum_events_page ON rum_events(page)",
                "CREATE INDEX IF NOT EXISTS ix_rum_events_js_error_name ON rum_events(js_error_name)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "rum_monitors" not in tables:
            cur.execute(
                """
                CREATE TABLE rum_monitors (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    app_id VARCHAR(64),
                    environment VARCHAR(64),
                    metric_name VARCHAR(64),
                    threshold_value FLOAT,
                    threshold_op VARCHAR(8),
                    window_minutes INTEGER,
                    enabled BOOLEAN,
                    created_by VARCHAR(320)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_rum_monitors_metric_name ON rum_monitors(metric_name)",
                "CREATE INDEX IF NOT EXISTS ix_rum_monitors_enabled ON rum_monitors(enabled)",
                "CREATE INDEX IF NOT EXISTS ix_rum_monitors_app_id ON rum_monitors(app_id)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "apm_monitors" not in tables:
            cur.execute(
                """
                CREATE TABLE apm_monitors (
                    id INTEGER PRIMARY KEY,
                    created_at DATETIME,
                    updated_at DATETIME,
                    name VARCHAR(128) UNIQUE,
                    app_id VARCHAR(64),
                    environment VARCHAR(64),
                    monitor_type VARCHAR(32),
                    metric_name VARCHAR(64),
                    threshold_value FLOAT,
                    threshold_op VARCHAR(8),
                    window_minutes INTEGER,
                    enabled BOOLEAN,
                    auto_generated BOOLEAN,
                    created_by VARCHAR(320)
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_apm_monitors_metric_name ON apm_monitors(metric_name)",
                "CREATE INDEX IF NOT EXISTS ix_apm_monitors_monitor_type ON apm_monitors(monitor_type)",
                "CREATE INDEX IF NOT EXISTS ix_apm_monitors_enabled ON apm_monitors(enabled)",
                "CREATE INDEX IF NOT EXISTS ix_apm_monitors_auto_generated ON apm_monitors(auto_generated)",
                "CREATE INDEX IF NOT EXISTS ix_apm_monitors_app_id ON apm_monitors(app_id)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        if "monitor_alerts" not in tables:
            cur.execute(
                """
                CREATE TABLE monitor_alerts (
                    id INTEGER PRIMARY KEY,
                    ts DATETIME,
                    source_type VARCHAR(16),
                    monitor_id INTEGER,
                    monitor_name VARCHAR(128),
                    app_id VARCHAR(64),
                    environment VARCHAR(64),
                    severity VARCHAR(16),
                    status VARCHAR(16),
                    metric_name VARCHAR(64),
                    observed_value FLOAT,
                    threshold_value FLOAT,
                    context_json TEXT
                )
                """
            )
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS ix_monitor_alerts_ts ON monitor_alerts(ts)",
                "CREATE INDEX IF NOT EXISTS ix_monitor_alerts_source_type ON monitor_alerts(source_type)",
                "CREATE INDEX IF NOT EXISTS ix_monitor_alerts_monitor_id ON monitor_alerts(monitor_id)",
                "CREATE INDEX IF NOT EXISTS ix_monitor_alerts_status ON monitor_alerts(status)",
                "CREATE INDEX IF NOT EXISTS ix_monitor_alerts_app_id ON monitor_alerts(app_id)",
            ]:
                try:
                    cur.execute(idx_sql)
                except Exception:
                    pass

        con.commit()
    except Exception:
        # Do not crash the app for migrations in a demo environment.
        return
    finally:
        try:
            con.close()
        except Exception:
            pass


def get_session() -> Session:
    return SessionLocal()
