#!/usr/bin/env python3
"""Seed demo data for Service Map + APM Errors pages.

Usage:
  python3 scripts/seed_apm_service_map_demo.py
  python3 scripts/seed_apm_service_map_demo.py --db data/dashboard.db --keep-existing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _norm_error_type(error_text: str, stack_text: str) -> str:
    et = (error_text or "").strip()
    if ":" in et:
        left = et.split(":", 1)[0].strip()
        if left:
            return left[:128]
    for ln in (stack_text or "").splitlines():
        line = ln.strip()
        if not line:
            continue
        if ":" in line:
            left = line.split(":", 1)[0].strip()
            if left and len(left) <= 128 and " " not in left:
                return left
    return "error"


def _signature(app_id: str, environment: str, service_name: str, error_type: str, error_message: str) -> str:
    msg = re.sub(r"\d+", "<num>", (error_message or "").strip().lower())
    msg = re.sub(r"\s+", " ", msg)[:220]
    raw = f"{app_id}|{environment}|{service_name}|{error_type}|{msg}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def seed(db_path: Path, keep_existing: bool = False) -> None:
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiler_samples (
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
            details_json TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS db_query_samples (
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS dynamic_instrumentation_feedback (
            id INTEGER PRIMARY KEY,
            ts DATETIME,
            agent_name VARCHAR(128),
            app_id VARCHAR(64),
            rule_id INTEGER,
            status VARCHAR(32),
            message TEXT,
            details_json TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rum_events (
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rum_monitors (
            id INTEGER PRIMARY KEY,
            created_at DATETIME,
            updated_at DATETIME,
            name VARCHAR(128),
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS apm_monitors (
            id INTEGER PRIMARY KEY,
            created_at DATETIME,
            updated_at DATETIME,
            name VARCHAR(128),
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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_alerts (
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

    demo_apps = ["demo-checkout", "demo-payment", "demo-inventory", "demo-frontend"]

    if not keep_existing:
        cur.execute("SELECT id FROM trace_runs WHERE app_id LIKE 'demo-%' OR provider='demo-seed'")
        run_ids = [int(r[0]) for r in cur.fetchall()]
        if run_ids:
            marks = ",".join("?" for _ in run_ids)
            cur.execute(f"DELETE FROM trace_spans WHERE trace_run_id IN ({marks})", run_ids)
            cur.execute(f"DELETE FROM apm_error_events WHERE trace_run_id IN ({marks})", run_ids)
            cur.execute(f"DELETE FROM trace_runs WHERE id IN ({marks})", run_ids)

        cur.execute("SELECT id FROM apm_error_groups WHERE app_id LIKE 'demo-%' OR error_message LIKE '%[DEMO]%'")
        grp_ids = [int(r[0]) for r in cur.fetchall()]
        if grp_ids:
            marks = ",".join("?" for _ in grp_ids)
            cur.execute(f"DELETE FROM apm_error_events WHERE error_group_id IN ({marks})", grp_ids)
            cur.execute(f"DELETE FROM apm_error_groups WHERE id IN ({marks})", grp_ids)
        cur.execute("DELETE FROM profiler_samples WHERE app_id LIKE 'demo-%'")
        cur.execute("DELETE FROM db_query_samples WHERE app_id LIKE 'demo-%'")
        cur.execute("DELETE FROM dynamic_instrumentation_feedback WHERE app_id LIKE 'demo-%' OR agent_name='netra-demo'")
        cur.execute("DELETE FROM rum_events WHERE app_id LIKE 'demo-%'")
        cur.execute("DELETE FROM rum_monitors WHERE app_id LIKE 'demo-%' OR app_id IS NULL")
        cur.execute("DELETE FROM apm_monitors WHERE app_id LIKE 'demo-%' OR app_id IS NULL")
        cur.execute("DELETE FROM monitor_alerts WHERE app_id LIKE 'demo-%' OR app_id IS NULL")

    now = _now_utc()

    def add_run(
        *,
        app_id: str,
        agent_id: str,
        env_name: str,
        idx: int,
        duration_ms: int,
        edges: list[tuple[str, int]],
        version: str,
    ) -> int:
        ts = now - timedelta(seconds=idx * 7)
        output = {
            "trace": {
                "name": "api.request",
                "environment": env_name,
                "spans": [
                    {"name": "trace.total", "duration_ms": duration_ms},
                ],
            },
            "env": {"environment": env_name, "version": version},
        }
        cur.execute(
            """
            INSERT INTO trace_runs (
                ts, scenario_run_id, project_id, app_id, agent_id,
                provider, model, name, status,
                input_json, output_json, error, duration_ms
            ) VALUES (?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                ts.isoformat(sep=" "),
                app_id,
                agent_id,
                "demo-seed",
                "demo-model",
                "api.request",
                "completed",
                json.dumps({"demo": True, "env": env_name}),
                json.dumps(output),
                int(duration_ms),
            ),
        )
        run_id = int(cur.lastrowid)

        start = ts
        end = ts + timedelta(milliseconds=duration_ms)
        cur.execute(
            """
            INSERT INTO trace_spans (trace_run_id, parent_id, name, start_ts, end_ts, duration_ms, meta_json)
            VALUES (?, NULL, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                "trace.total",
                start.isoformat(sep=" "),
                end.isoformat(sep=" "),
                int(duration_ms),
                json.dumps({"demo": True, "service": app_id, "memory_bytes": 32_000_000 + idx * 250_000}),
            ),
        )
        parent_span_id = int(cur.lastrowid)

        offset = 10
        for target, edge_ms in edges:
            s = ts + timedelta(milliseconds=offset)
            e = s + timedelta(milliseconds=edge_ms)
            meta = {
                "target_service": target,
                "downstream_service": target,
                "environment": env_name,
                "service_name": app_id,
                "memory_bytes": 8_000_000 + edge_ms * 1000,
                "demo": True,
            }
            if target in {"warehouse-db", "bank-gateway"}:
                meta.update(
                    {
                        "db_system": "postgres",
                        "db_instance": "orders-primary",
                        "db_query": "SELECT * FROM orders WHERE order_id = 10342",
                        "rows_examined": 1200,
                        "rows_returned": 1,
                        "wait_event": "IO:DataFileRead",
                        "explain_plan": {"plan": "Index Scan using orders_pkey on orders", "cost": "0.43..8.45"},
                    }
                )
            cur.execute(
                """
                INSERT INTO trace_spans (trace_run_id, parent_id, name, start_ts, end_ts, duration_ms, meta_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    parent_span_id,
                    f"http.client.{target}",
                    s.isoformat(sep=" "),
                    e.isoformat(sep=" "),
                    int(edge_ms),
                    json.dumps(meta),
                ),
            )
            offset += edge_ms + 8

        return run_id

    run_ids: list[int] = []
    # prod traffic
    run_ids.append(add_run(app_id="demo-frontend", agent_id="netra-demo", env_name="prod", idx=0, duration_ms=420, edges=[("demo-checkout", 180)], version="v2.4.1"))
    run_ids.append(add_run(app_id="demo-checkout", agent_id="netra-demo", env_name="prod", idx=1, duration_ms=390, edges=[("demo-payment", 140), ("demo-inventory", 120)], version="v2.4.1"))
    run_ids.append(add_run(app_id="demo-payment", agent_id="netra-demo", env_name="prod", idx=2, duration_ms=240, edges=[("bank-gateway", 110)], version="v2.4.1"))
    run_ids.append(add_run(app_id="demo-inventory", agent_id="netra-demo", env_name="prod", idx=3, duration_ms=210, edges=[("warehouse-db", 95)], version="v2.4.1"))

    # staging traffic
    run_ids.append(add_run(app_id="demo-frontend", agent_id="netra-demo", env_name="staging", idx=4, duration_ms=510, edges=[("demo-checkout", 220)], version="v2.5.0-rc1"))
    run_ids.append(add_run(app_id="demo-checkout", agent_id="netra-demo", env_name="staging", idx=5, duration_ms=470, edges=[("demo-payment", 210), ("demo-inventory", 160)], version="v2.5.0-rc1"))

    # APM groups + events
    groups = [
        {
            "app_id": "demo-checkout",
            "environment": "prod",
            "service": "checkout-service",
            "handled": False,
            "workflow": "open",
            "message": "ValueError: [DEMO] invalid cart state for order_id=10342",
            "stack": "Traceback (most recent call last):\\nValueError: invalid cart state",
            "assignee": "",
            "notes": "",
            "run_id": run_ids[1],
            "events": 3,
        },
        {
            "app_id": "demo-payment",
            "environment": "prod",
            "service": "payment-service",
            "handled": True,
            "workflow": "ack",
            "message": "TimeoutError: [DEMO] upstream bank timeout txn=778812",
            "stack": "Traceback (most recent call last):\\nTimeoutError: upstream timeout",
            "assignee": "oncall@demo.local",
            "notes": "Investigating bank latency spike",
            "run_id": run_ids[2],
            "events": 2,
        },
        {
            "app_id": "demo-checkout",
            "environment": "staging",
            "service": "checkout-service",
            "handled": False,
            "workflow": "resolved",
            "message": "KeyError: [DEMO] coupon_code missing in payload request_id=9921",
            "stack": "Traceback (most recent call last):\\nKeyError: coupon_code",
            "assignee": "qa@demo.local",
            "notes": "Fixed in staging build",
            "run_id": run_ids[5],
            "events": 1,
        },
    ]

    group_count = 0
    event_count = 0

    for gi, g in enumerate(groups):
        etype = _norm_error_type(g["message"], g["stack"])
        sig = _signature(g["app_id"], g["environment"], g["service"], etype, g["message"])
        first_seen = now - timedelta(minutes=12 - gi * 2)
        last_seen = now - timedelta(minutes=max(1, 8 - gi * 2))

        cur.execute(
            """
            INSERT INTO apm_error_groups (
                created_at, updated_at, first_seen_ts, last_seen_ts,
                signature, error_type, error_message, service_name,
                app_id, environment, handled, occurrence_count,
                workflow_status, assignee, workflow_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                first_seen.isoformat(sep=" "),
                now.isoformat(sep=" "),
                first_seen.isoformat(sep=" "),
                last_seen.isoformat(sep=" "),
                sig,
                etype,
                g["message"],
                g["service"],
                g["app_id"],
                g["environment"],
                1 if g["handled"] else 0,
                int(g["events"]),
                g["workflow"],
                g["assignee"] or None,
                g["notes"] or None,
            ),
        )
        group_id = int(cur.lastrowid)
        group_count += 1

        for ei in range(int(g["events"])):
            ets = now - timedelta(minutes=6 - gi, seconds=ei * 19)
            replay = {
                "trace_run_id": int(g["run_id"]),
                "environment": g["environment"],
                "service_name": g["service"],
                "app_id": g["app_id"],
                "error_type": etype,
                "error_message": g["message"],
                "debug": {
                    "request_id": f"demo-req-{gi}-{ei}",
                    "user_id": f"demo-user-{100+ei}",
                    "endpoint": "/api/checkout" if "checkout" in g["app_id"] else "/api/payments",
                },
                "sample_payload": {
                    "path": "/v1/demo",
                    "method": "POST",
                    "status_code": 500 if not g["handled"] else 504,
                },
                "ts": _iso(ets),
            }
            cur.execute(
                """
                INSERT INTO apm_error_events (
                    created_at, ts, error_group_id, trace_run_id,
                    app_id, agent_id, service_name, environment,
                    handled, error_type, error_message, stack_trace, replay_context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ets.isoformat(sep=" "),
                    ets.isoformat(sep=" "),
                    group_id,
                    int(g["run_id"]),
                    g["app_id"],
                    "netra-demo",
                    g["service"],
                    g["environment"],
                    1 if g["handled"] else 0,
                    etype,
                    g["message"],
                    g["stack"],
                    json.dumps(replay),
                ),
            )
            event_count += 1

    profiler_rows = [
        ("demo-checkout", "netra-demo", "prod", "checkout-service", "http.client.demo-payment", "v2.4.1", run_ids[1], "cpu", 145.0, 54_000_000),
        ("demo-checkout", "netra-demo", "prod", "checkout-service", "http.client.demo-inventory", "v2.4.1", run_ids[1], "cpu", 121.0, 49_000_000),
        ("demo-checkout", "netra-demo", "staging", "checkout-service", "http.client.demo-payment", "v2.5.0-rc1", run_ids[5], "cpu", 208.0, 69_000_000),
        ("demo-checkout", "netra-demo", "staging", "checkout-service", "http.client.demo-inventory", "v2.5.0-rc1", run_ids[5], "cpu", 163.0, 64_000_000),
        ("demo-payment", "netra-demo", "prod", "payment-service", "http.client.bank-gateway", "v2.4.1", run_ids[2], "cpu", 111.0, 37_000_000),
    ]
    for app_id, agent_id, env_name, svc, method, ver, rid, stype, cpu_ms, mem_b in profiler_rows:
        ts = now - timedelta(minutes=3)
        cur.execute(
            """
            INSERT INTO profiler_samples (
                ts, app_id, agent_id, environment, service_name, method_name,
                version, trace_run_id, sample_type, cpu_ms, memory_bytes, sample_count, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts.isoformat(sep=" "),
                app_id,
                agent_id,
                env_name,
                svc,
                method,
                ver,
                int(rid),
                stype,
                float(cpu_ms),
                int(mem_b),
                1,
                json.dumps({"demo": True}),
            ),
        )

    dbm_rows = [
        ("demo-inventory", "netra-demo", "prod", "postgres", "orders-primary", "inventory-service", "SELECT * FROM orders WHERE order_id = 10342", "SELECT", 95.0, 1200, 1, "IO:DataFileRead"),
        ("demo-payment", "netra-demo", "prod", "postgres", "payments-primary", "payment-service", "SELECT * FROM transactions WHERE txn_id = 778812", "SELECT", 510.0, 2400, 1, "Lock:transactionid"),
        ("demo-checkout", "netra-demo", "staging", "postgres", "orders-staging", "checkout-service", "UPDATE carts SET status='processing' WHERE cart_id = 9921", "UPDATE", 330.0, 450, 1, "CPU"),
    ]
    for app_id, agent_id, env_name, db_system, db_inst, svc, qtext, qtype, dur, rex, rret, wait in dbm_rows:
        ts = now - timedelta(minutes=2)
        cur.execute(
            """
            INSERT INTO db_query_samples (
                ts, app_id, agent_id, environment, db_system, db_instance, service_name,
                query_fingerprint, query_text, query_type, duration_ms, rows_examined,
                rows_returned, wait_event, explain_plan_json, meta_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts.isoformat(sep=" "),
                app_id,
                agent_id,
                env_name,
                db_system,
                db_inst,
                svc,
                _signature(app_id, env_name, svc, qtype, qtext),
                qtext,
                qtype,
                float(dur),
                int(rex),
                int(rret),
                wait,
                json.dumps({"plan": "demo"}),
                json.dumps({"demo": True}),
            ),
        )

    feedback_rows = [
        ("netra-demo", "demo-checkout", None, "applied", "Loaded 3 dynamic rules"),
        ("netra-demo", "demo-checkout", 1, "applied", "Rule applied: extra span tags enabled"),
        ("netra-demo", "demo-payment", 2, "failed", "Rule rejected: invalid condition expression"),
        ("netra-demo", "demo-inventory", 3, "skipped", "Rule scope mismatch for current app"),
    ]
    for agent_name, app_id, rule_id, status, msg in feedback_rows:
        ts = now - timedelta(minutes=1)
        cur.execute(
            """
            INSERT INTO dynamic_instrumentation_feedback (
                ts, agent_name, app_id, rule_id, status, message, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts.isoformat(sep=" "),
                agent_name,
                app_id,
                rule_id,
                status,
                msg,
                json.dumps({"demo": True, "source": "seed"}),
            ),
        )

    rum_rows = [
        ("demo-frontend", "browser-sdk", "prod", "web", "desktop", "sess-1", "user-h1", "/checkout", "page_view", 840.0, 1900.0, 120.0, 0.09, "", ""),
        ("demo-frontend", "browser-sdk", "prod", "web", "mobile", "sess-2", "user-h2", "/payment", "click_buy", 1120.0, 2700.0, 180.0, 0.16, "TypeError", "undefined is not a function"),
        ("demo-frontend", "browser-sdk", "staging", "web", "desktop", "sess-3", "user-h3", "/cart", "page_view", 760.0, 1500.0, 90.0, 0.06, "", ""),
    ]
    for app_id, agent_id, env_name, platform, dev, sess, user_h, page, action, load_ms, lcp, fid, cls, err_n, err_m in rum_rows:
        ts = now - timedelta(minutes=4)
        cur.execute(
            """
            INSERT INTO rum_events (
                ts, app_id, agent_id, environment, platform, device_type, session_id, user_id_hash, page, action,
                load_time_ms, lcp_ms, fid_ms, cls, js_error_name, js_error_message, release_version, meta_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts.isoformat(sep=" "),
                app_id,
                agent_id,
                env_name,
                platform,
                dev,
                sess,
                user_h,
                page,
                action,
                load_ms,
                lcp,
                fid,
                cls,
                (err_n or None),
                (err_m or None),
                "web-2.5.0",
                json.dumps({"demo": True}),
            ),
        )

    cur.execute(
        """
        INSERT INTO rum_monitors (
            created_at, updated_at, name, app_id, environment, metric_name, threshold_value, threshold_op, window_minutes, enabled, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (now.isoformat(sep=" "), now.isoformat(sep=" "), "demo-rum-lcp", "demo-frontend", "prod", "lcp_ms", 2500.0, ">", 15, 1, "seed"),
    )
    cur.execute(
        """
        INSERT INTO apm_monitors (
            created_at, updated_at, name, app_id, environment, monitor_type, metric_name, threshold_value, threshold_op, window_minutes, enabled, auto_generated, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (now.isoformat(sep=" "), now.isoformat(sep=" "), "demo-apm-error-rate", "demo-checkout", "prod", "metric", "error_rate_percent", 2.0, ">", 15, 1, 0, "seed"),
    )
    cur.execute(
        """
        INSERT INTO monitor_alerts (
            ts, source_type, monitor_id, monitor_name, app_id, environment, severity, status, metric_name, observed_value, threshold_value, context_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (now.isoformat(sep=" "), "rum", 1, "demo-rum-lcp", "demo-frontend", "prod", "warning", "open", "lcp_ms", 2700.0, 2500.0, json.dumps({"demo": True})),
    )

    con.commit()

    print("seed complete")
    print(f"trace_runs_added={len(run_ids)}")
    print(f"trace_spans_added~={len(run_ids) * 2 + 4}")
    print(f"apm_error_groups_added={group_count}")
    print(f"apm_error_events_added={event_count}")
    print("apps=", ", ".join(demo_apps))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed demo APM + Service Map data")
    parser.add_argument("--db", default="data/dashboard.db", help="SQLite DB path")
    parser.add_argument("--keep-existing", action="store_true", help="Do not delete previous demo-seed rows")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        raise SystemExit(f"DB not found: {db_path}")
    seed(db_path, keep_existing=bool(args.keep_existing))
