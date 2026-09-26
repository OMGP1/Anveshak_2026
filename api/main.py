from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
from typing import Any, Literal

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.replay import (
    METRICS_INTERVAL_S,
    QUEUE_CAPACITY,
    FrameQueue,
    ReplayController,
    scenario_list,
    validate_mode,
    validate_speed,
)
from api.store import DEFAULT_DB, DEFAULT_LEDGER, AlertStore
from api.case_store import CaseConflict, CollaborationStore
from copilot.service import CopilotService
from api.training_jobs import TrainingJobs
from training.inventory import inspect_datasets
from engine.detect.coverage import method_coverage
from api.live import MonitoringController
from engine.sources.live_source import interfaces as capture_interfaces

TITLE = "SIH26145 detection enclave"


class StartRequest(BaseModel):
    scenario: str
    speed: float = 1.0
    mode: str = "realtime"
    source: Literal["pcap", "rust-pcap", "flows"] = "pcap"


class LiveStartRequest(BaseModel):
    interface: str
    capture_filter: str = "ip"


class CaseCommandRequest(BaseModel):
    action: Literal["claim", "release", "annotate", "set_status", "review"]
    expected_version: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=4000)
    status: Literal["open", "investigating", "escalated", "closed"] | None = None
    label: Literal["confirmed-benign", "suspicious-needs-investigation", "confirmed-malicious", "inconclusive"] | None = None
    reason: str | None = Field(default=None, max_length=4000)


class ReviewRequest(BaseModel):
    expected_version: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=128)
    label: Literal["confirmed-benign", "suspicious-needs-investigation", "confirmed-malicious", "inconclusive"]
    reason: str = Field(min_length=1, max_length=4000)


class CopilotRequest(BaseModel):
    intent: Literal["explain_alert", "summarise_window", "compare_alerts", "explain_term", "draft_incident_report"]
    alert_ids: list[str] = Field(default_factory=list, max_length=20)
    since: str | None = None
    until: str | None = None
    threat_class: str | None = None
    term: str | None = Field(default=None, max_length=128)
    language: str = Field(default="en", pattern="^[a-z]{2}(-[A-Z]{2})?$")
    style: Literal["plain_english", "technical"] = "plain_english"
    human_fields: dict[str, str] = Field(default_factory=dict)


class ReportReviewRequest(BaseModel):
    expected_version: int = Field(ge=1)
    status: Literal["human_reviewed", "exported", "submission_recorded"]


class Hub:
    def __init__(self) -> None:
        self.clients: dict[WebSocket, str] = {}

    def add(self, socket: WebSocket, role: str) -> None:
        self.clients[socket] = role

    def discard(self, socket: WebSocket) -> None:
        self.clients.pop(socket, None)

    async def broadcast(self, frame: dict, roles: set[str] | None = None) -> None:
        async def send(socket: WebSocket) -> None:
            try:
                await asyncio.wait_for(socket.send_json(frame), timeout=2.0)
            except (RuntimeError, WebSocketDisconnect, OSError, asyncio.TimeoutError):
                self.discard(socket)
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(socket.close(code=1013), timeout=0.2)
        sockets = [socket for socket, role in list(self.clients.items()) if roles is None or role in roles]
        await asyncio.gather(*(send(socket) for socket in sockets))


def create_app(db_path: str = DEFAULT_DB, ledger_path: str = DEFAULT_LEDGER) -> FastAPI:
    production = os.environ.get("SIH_PRODUCTION") == "1"
    gateway_secret = os.environ.get("SIH_GATEWAY_SECRET", "")
    secret_file = os.environ.get("SIH_GATEWAY_SECRET_FILE")
    if secret_file:
        gateway_secret = Path(secret_file).read_text().strip()
    if production and len(gateway_secret) < 32:
        raise ValueError("Production mode requires a gateway secret of at least 32 characters")
    if production:
        from engine.models.integrity import require_verified_bundle
        from engine.models.tier1 import MODEL_DIR
        require_verified_bundle(MODEL_DIR)
    state_dir = Path(os.environ["SIH_STATE_DIR"]) if os.environ.get("SIH_STATE_DIR") else None
    if state_dir:
        db_path = str(state_dir / "alerts.duckdb") if db_path == DEFAULT_DB else db_path
        ledger_path = str(state_dir / "alerts.jsonl") if ledger_path == DEFAULT_LEDGER else ledger_path
    queue = FrameQueue(QUEUE_CAPACITY)
    store = AlertStore(db_path, ledger_path)
    if db_path == ":memory:":
        collaboration_path = ":memory:"
    elif state_dir:
        collaboration_path = str(state_dir / "collaboration.duckdb")
    else:
        collaboration_path = str(Path(db_path).with_name("collaboration.duckdb"))
    collaboration = CollaborationStore(collaboration_path)
    copilot = CopilotService(store, collaboration)
    config_path = os.environ.get("SIH_ENGINE_CONFIG")
    config = json.loads(Path(config_path).read_text()) if config_path else {}
    if not isinstance(config, dict):
        store.close()
        raise ValueError("SIH_ENGINE_CONFIG must contain a JSON object")
    controller = MonitoringController(queue, store, config)
    hub = Hub()
    jobs = TrainingJobs(directory=state_dir / "training-runs" if state_dir else None)
    operator_token = gateway_secret or os.environ.get("SIH_OPERATOR_TOKEN", "")
    auto_train = os.environ.get("SIH_AUTO_TRAIN") == "1"
    if auto_train and len(operator_token) < 32:
        store.close()
        raise ValueError("SIH_AUTO_TRAIN requires SIH_OPERATOR_TOKEN with at least 32 characters")

    async def training_watcher() -> None:
        while True:
            if auto_train:
                await asyncio.to_thread(jobs.auto_check)
            await asyncio.sleep(60)

    async def pump() -> None:
        while True:
            frames = await queue.drain(timeout=1.0)
            for frame in frames:
                await hub.broadcast(frame)

    async def ticker() -> None:
        while True:
            await asyncio.sleep(METRICS_INTERVAL_S)
            if hub.clients:
                queue.offer("metrics", controller.metrics())
                queue.offer("status", controller.status())

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        queue.bind(asyncio.get_running_loop())
        tasks = [asyncio.create_task(pump()), asyncio.create_task(ticker()),
                 asyncio.create_task(training_watcher())]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            controller.stop()
            await asyncio.to_thread(jobs.close)
            await asyncio.to_thread(copilot.close)
            queue.unbind()
            collaboration.close()
            store.close()

    app = FastAPI(title=TITLE, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.queue = queue
    app.state.store = store
    app.state.controller = controller
    app.state.hub = hub
    app.state.training_jobs = jobs
    app.state.collaboration = collaboration
    app.state.copilot = copilot

    @app.middleware("http")
    async def local_write_guard(request: Request, call_next):
        if gateway_secret:
            if not hmac.compare_digest(request.headers.get("x-sih-gateway", ""), gateway_secret):
                return JSONResponse({"detail": "Trusted gateway required"}, status_code=401)
            role = request.headers.get("x-sih-role", "")
            if role not in {"viewer", "operator", "admin"}:
                return JSONResponse({"detail": "Invalid gateway role"}, status_code=403)
            if request.headers.get("x-sih-user", "").strip() == "":
                return JSONResponse({"detail": "Trusted gateway actor required"}, status_code=401)
            if (request.url.path.startswith("/api/cases") or request.url.path.startswith("/api/reports/")) and role == "viewer":
                return JSONResponse({"detail": "Role denied"}, status_code=403)
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                if request.url.path.startswith("/api/training/"):
                    needed = {"admin"}
                elif request.url.path.startswith("/api/copilot/"):
                    needed = {"viewer", "operator", "admin"}
                else:
                    needed = {"operator", "admin"}
                if role not in needed:
                    return JSONResponse({"detail": "Role denied"}, status_code=403)
        origin = request.headers.get("origin")
        if not gateway_secret and request.method not in ("GET", "HEAD", "OPTIONS") and origin:
            allowed = {str(request.base_url).rstrip("/"), "http://localhost:5173", "http://127.0.0.1:5173"}
            if origin not in allowed:
                return JSONResponse({"detail": "Cross-origin mutation refused"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin" if gateway_secret else "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def get_health() -> dict:
        return {"status": "degraded" if getattr(controller, "error", None) else "ok",
                "deployment": "hardened-single-node" if production else "single-process-local", "production_ready": False,
                "gateway_required": bool(gateway_secret), "signed_models_required": production,
                "replay_error": getattr(controller, "error", None),
                "limits": {"websocket_clients": 32, "queue": QUEUE_CAPACITY, "training_workers": 1,
                           "copilot_active": 1, "copilot_queued": 4},
                "novelty": getattr(controller.engine, "novelty", None).stats()
                           if getattr(controller.engine, "novelty", None) else {"status": "unavailable"}}

    @app.get("/api/datasets")
    def get_datasets() -> dict:
        return inspect_datasets()

    @app.get("/api/detection-coverage")
    def get_detection_coverage() -> dict:
        return method_coverage(getattr(controller.engine, "config", controller.config), source_kind=controller.source_kind)

    @app.get("/api/training")
    def get_training(request: Request) -> dict:
        authorized = not gateway_secret or request.headers.get("x-sih-role") == "admin"
        return {**jobs.status(), "enabled": len(operator_token) >= 32 and authorized,
                "gateway_session": bool(gateway_secret), "auto_train": auto_train}

    @app.post("/api/training/start", status_code=202)
    def start_training(authorization: str | None = Header(default=None)) -> dict:
        if len(operator_token) < 32:
            raise HTTPException(503, "Set SIH_OPERATOR_TOKEN (at least 32 characters) to enable training")
        if not hmac.compare_digest(authorization or "", "Bearer " + operator_token):
            raise HTTPException(401, "Valid operator token required")
        try:
            return jobs.start()
        except (RuntimeError, OSError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/scenarios")
    def get_scenarios() -> list[dict]:
        return scenario_list()

    @app.get("/api/status")
    def get_status() -> dict:
        return controller.status()

    @app.get("/api/live/interfaces")
    def get_live_interfaces() -> dict:
        return capture_interfaces()

    @app.get("/api/live/status")
    def get_live_status() -> dict:
        return controller.live_status()

    @app.post("/api/live/start")
    def post_live_start(request: LiveStartRequest) -> dict:
        try:
            return controller.start_live(request.interface, request.capture_filter)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/live/stop")
    def post_live_stop(session_id: str | None = None) -> dict:
        with controller._control_lock:
            if session_id is not None and session_id != controller.live_session:
                raise HTTPException(409, "Live session changed; the requested session will not stop another session")
            if controller.source_kind != "live":
                raise HTTPException(409, "No live session is active; replay controls are separate")
            controller.stop()
            return controller.live_status()

    @app.post("/api/replay/start")
    def post_start(request: StartRequest) -> dict:
        try:
            speed = validate_speed(request.speed)
            mode = validate_mode(request.mode)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            return controller.start(request.scenario, speed, mode, request.source)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown scenario {request.scenario!r}") from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"capture missing: {exc}") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/replay/pause")
    def post_pause() -> dict:
        try:
            return controller.pause()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/replay/resume")
    def post_resume() -> dict:
        return controller.resume()

    @app.post("/api/replay/stop")
    def post_stop() -> dict:
        return controller.stop()

    @app.get("/api/alerts")
    def get_alerts(
        since: str | None = None,
        limit: int = Query(200, ge=1, le=1000),
        threat_class: str | None = None,
    ) -> list[dict]:
        return store.recent(since=since, limit=limit, threat_class=threat_class)

    @app.get("/api/alerts/export")
    def export_alerts(format: Literal["json", "jsonl"] = "json", threat_class: str | None = None):
        media_type = "application/json" if format == "json" else "application/x-ndjson"
        return StreamingResponse(store.export_records(format, threat_class), media_type=media_type,
                                 headers={"Content-Disposition": f'attachment; filename="sih-alerts.{format}"'})

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: str) -> dict:
        alert = store.get(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"unknown alert {alert_id!r}")
        return alert

    def actor_of(request: Request) -> tuple[str, str]:
        return (request.headers.get("x-sih-user", "local-operator"),
                request.headers.get("x-sih-role", "admin" if not gateway_secret else ""))

    @app.get("/api/cases")
    def get_cases(limit: int = Query(200, ge=1, le=1000)) -> list[dict]:
        return collaboration.list_cases(limit=limit)

    @app.get("/api/cases/events")
    def get_case_events(after: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)) -> dict:
        return collaboration.events_after(after, limit)

    @app.get("/api/cases/{alert_id}")
    def get_case(alert_id: str) -> dict:
        case = collaboration.get_case(alert_id)
        if case is None:
            raise HTTPException(404, f"no case exists for alert {alert_id!r}")
        return case

    @app.post("/api/cases/{alert_id}/commands")
    async def post_case_command(alert_id: str, command: CaseCommandRequest, request: Request) -> dict:
        if store.get(alert_id) is None:
            raise HTTPException(404, f"unknown alert {alert_id!r}")
        actor, role = actor_of(request)
        try:
            result = collaboration.command(alert_id=alert_id, actor=actor, role=role,
                                           action=command.action, expected_version=command.expected_version,
                                           idempotency_key=command.idempotency_key,
                                           payload=command.model_dump(exclude_none=True))
        except CaseConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not result.get("idempotent_replay"):
            await hub.broadcast({"type": "case_delta", "payload": result["event"]}, {"operator", "admin"})
        return result

    @app.post("/api/alerts/{alert_id}/reviews")
    async def post_review(alert_id: str, review: ReviewRequest, request: Request) -> dict:
        command = CaseCommandRequest(action="review", expected_version=review.expected_version,
                                     idempotency_key=review.idempotency_key, label=review.label,
                                     reason=review.reason)
        return await post_case_command(alert_id, command, request)

    @app.post("/api/copilot/query", status_code=202)
    def post_copilot_query(query: CopilotRequest, request: Request) -> dict:
        actor, role = actor_of(request)
        return copilot.submit(query.model_dump(), actor=actor, scope=role)

    @app.get("/api/copilot/jobs/{job_id}")
    def get_copilot_job(job_id: str, request: Request) -> dict:
        actor, role = actor_of(request)
        job = copilot.get(job_id, actor=actor, scope=role)
        if job is None:
            raise HTTPException(404, "unknown or inaccessible copilot job")
        return job

    @app.post("/api/copilot/jobs/{job_id}/cancel")
    def cancel_copilot_job(job_id: str, request: Request) -> dict:
        actor, role = actor_of(request)
        job = copilot.cancel(job_id, actor=actor, scope=role)
        if job is None:
            raise HTTPException(404, "unknown or inaccessible copilot job")
        return job

    @app.get("/api/reports/{report_id}")
    def get_report(report_id: str) -> dict:
        report = collaboration.get_report(report_id)
        if report is None:
            raise HTTPException(404, "unknown report draft")
        return report

    @app.post("/api/reports/{report_id}/review")
    def review_report(report_id: str, review: ReportReviewRequest, request: Request) -> dict:
        actor, _role = actor_of(request)
        try:
            return collaboration.review_report(report_id, review.expected_version, actor, review.status)
        except KeyError as exc:
            raise HTTPException(404, "unknown report draft") from exc
        except CaseConflict as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/reports/{report_id}/export")
    def export_report(report_id: str, format: Literal["json", "markdown"] = "json"):
        report = collaboration.get_report(report_id)
        if report is None:
            raise HTTPException(404, "unknown report draft")
        if format == "markdown":
            return PlainTextResponse(report["markdown"], media_type="text/markdown",
                                     headers={"Content-Disposition": f'attachment; filename="{report_id}.md"'})
        return JSONResponse(report["document"],
                            headers={"Content-Disposition": f'attachment; filename="{report_id}.json"'})

    @app.get("/api/alert-history")
    def get_alert_history(after: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)) -> dict:
        return store.after(after, limit)

    @app.get("/api/metrics")
    def get_metrics() -> dict:
        return controller.metrics()

    @app.get("/api/coverage")
    def get_coverage() -> dict:
        return controller.coverage()

    @app.get("/api/novelty/status")
    def get_novelty_status() -> dict:
        monitor = getattr(controller.engine, "novelty", None)
        return monitor.stats() if monitor is not None else {"status": "unavailable"}

    @app.get("/api/ledger/verify")
    def get_ledger_verify() -> dict:
        return store.verify_ledger()

    @app.websocket("/ws")
    async def stream(socket: WebSocket) -> None:
        if gateway_secret and (not hmac.compare_digest(socket.headers.get("x-sih-gateway", ""), gateway_secret)
                               or socket.headers.get("x-sih-role") not in {"viewer", "operator", "admin"}
                               or not socket.headers.get("x-sih-user", "").strip()):
            await socket.close(code=1008)
            return
        origin = socket.headers.get("origin")
        host = socket.headers.get("host", "")
        if origin and origin not in {"http://localhost:5173", "http://127.0.0.1:5173",
                                      "http://" + host, "https://" + host}:
            await socket.close(code=1008)
            return
        if len(hub.clients) >= 32:
            await socket.close(code=1013)
            return
        await socket.accept()
        socket_role = socket.headers.get("x-sih-role", "admin" if not gateway_secret else "")
        hub.add(socket, socket_role)
        await socket.send_json({"type": "status", "payload": controller.status()})
        await socket.send_json({"type": "metrics", "payload": controller.metrics()})
        if socket_role in {"operator", "admin"}:
            await socket.send_json({"type": "case_cursor", "payload": collaboration.latest_event_sequence})
        try:
            while True:
                await socket.receive_text()
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.discard(socket)

    mount_dashboard(app)
    return app


DIST = Path(__file__).resolve().parents[1] / "ui" / "dist"
SIMPLE_DIST = Path(__file__).resolve().parents[1] / "ui-simple" / "dist"


def mount_dashboard(app: FastAPI) -> None:
    # The specific mount must precede the original dashboard's catch-all.
    if SIMPLE_DIST.is_dir():
        @app.get("/simple", include_in_schema=False)
        def simple_redirect(request: Request) -> RedirectResponse:
            # Root StaticFiles would otherwise consume the slashless path
            # before the router can issue its usual trailing-slash redirect.
            return RedirectResponse(str(request.url.replace(path=request.url.path + "/")))

        app.mount("/simple", StaticFiles(directory=SIMPLE_DIST, html=True), name="simple-dashboard")
    else:
        @app.get("/simple/")
        @app.get("/simple", include_in_schema=False)
        def simple_not_built() -> dict:
            return {"detail": "simple dashboard not built: run npm ci and npm run build in ui-simple/"}

    if DIST.is_dir():
        app.mount("/", StaticFiles(directory=DIST, html=True), name="dashboard")
        return

    @app.get("/")
    def not_built() -> dict:
        return {"detail": "dashboard not built: run npm install and npm run build in ui/"}


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)


def main() -> None:
    import uvicorn

    host = os.environ.get("SIH_API_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "::1"} and os.environ.get("SIH_PRODUCTION") != "1":
        raise ValueError("Non-loopback API binding requires production mode")
    uvicorn.run(create_app(), host=host, port=int(os.environ.get("SIH_API_PORT", "8000")), log_level="info", proxy_headers=False,
                limit_concurrency=160, timeout_keep_alive=15, ws_max_size=4096, ws_ping_timeout=20)


if __name__ == "__main__":
    main()
