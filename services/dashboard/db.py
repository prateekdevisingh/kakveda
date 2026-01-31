from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine
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


class ScenarioRun(Base):
    __tablename__ = "scenario_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    app_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    prompt: Mapped[str] = mapped_column(Text)
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
