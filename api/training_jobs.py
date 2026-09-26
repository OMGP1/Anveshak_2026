"""Single-worker candidate jobs with immutable inputs, a timeout, and opt-in watching."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import uuid

from training.candidate import PROFILE, ROOT
from engine.models.tier1 import sha256_file


class TrainingJobs:
    def __init__(self, directory: Path | None = None, dataset_dir: Path | None = None) -> None:
        self.directory = Path(directory or ROOT / "data/training-runs")
        self.dataset_dir = Path(dataset_dir or ROOT / "data/models")
        self._lock = threading.RLock()
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._closed = False
        self._state: dict = {"state": "idle", "serving_model_changed": False}
        self._attempted_digest: str | None = None
        self._last_auto_check = 0.0

    def status(self) -> dict:
        with self._lock:
            return dict(self._state)

    def start(self) -> dict:
        with self._lock:
            if self._closed:
                raise RuntimeError("Training manager is shutting down")
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("A training job is already running")
            profile = json.loads(PROFILE.read_text())
            self.directory.mkdir(parents=True, exist_ok=True)
            if sum(p.is_dir() for p in self.directory.iterdir()) >= profile["max_runs"]:
                raise RuntimeError("Training run limit reached; archive reviewed runs before training again")
            if (self.dataset_dir / "dataset.parquet").stat().st_size > 256 * 1024 * 1024:
                raise RuntimeError("Dataset exceeds the local training memory budget (256 MiB input)")
            if shutil.disk_usage(self.directory).free < 1024 ** 3:
                raise RuntimeError("Training requires at least 1 GiB of free disk space")
            job_id = uuid.uuid4().hex
            run = self.directory / job_id
            run.mkdir(mode=0o700)
            for name in ("dataset.parquet", "dataset_manifest.json"):
                shutil.copyfile(self.dataset_dir / name, run / name)
            (run / "profile.json").write_text(json.dumps(profile, indent=2) + "\n")
            self._state = {"id": job_id, "state": "running", "started_at": time.time(),
                           "profile": profile["profile"], "serving_model_changed": False}
            self._save(run)
            self._thread = threading.Thread(target=self._run, args=(run, profile["timeout_s"]), daemon=True)
            self._thread.start()
            return dict(self._state)

    def _save(self, run: Path) -> None:
        temporary = run / "status.tmp"
        temporary.write_text(json.dumps(self._state, indent=2) + "\n")
        temporary.replace(run / "status.json")

    def _run(self, run: Path, timeout: int) -> None:
        environment = dict(os.environ)
        # Candidate artifacts are isolated, untrusted outputs, never serving inputs.
        for name in ("SIH_PRODUCTION", "SIH_MODEL_DIR", "SIH_MODEL_PUBLIC_KEY", "SIH_GATEWAY_SECRET",
                     "SIH_GATEWAY_SECRET_FILE", "SIH_OPERATOR_TOKEN"):
            environment.pop(name, None)
        environment.update(OMP_NUM_THREADS="2", OPENBLAS_NUM_THREADS="2", MKL_NUM_THREADS="2",
                           MPLCONFIGDIR=str(run / "matplotlib"))
        try:
            with (run / "worker.log").open("w") as log:
                with self._lock:
                    if self._closed:
                        raise RuntimeError("Training cancelled during shutdown")
                    self._process = subprocess.Popen(
                        [sys.executable, "-m", "training.candidate", str(run.resolve())],
                        cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT,
                    )
                try:
                    code = self._process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()
                    raise RuntimeError(f"Training exceeded its {timeout} second timeout")
            if code != 0:
                raise RuntimeError(f"Training worker exited with code {code}; inspect worker.log")
            result = json.loads((run / "result.json").read_text())
            with self._lock:
                self._state.update(state=result["state"], gates=result["gates"],
                                   model_hash=result["model_hash"],
                                   pr_auc=result["evaluation"]["pr_auc_attack_vs_benign"])
        except Exception as exc:
            with self._lock:
                self._state.update(state="failed", error=str(exc))
        finally:
            with self._lock:
                self._state["finished_at"] = time.time()
                self._process = None
                self._save(run)

    def auto_check(self) -> None:
        """At most one attempt per verified dataset digest per process. No pseudo-labelling."""
        with self._lock:
            if self._closed or self._state["state"] == "running" or time.monotonic() - self._last_auto_check < 60:
                return
            self._last_auto_check = time.monotonic()
        try:
            manifest = json.loads((self.dataset_dir / "dataset_manifest.json").read_text())
            digest = sha256_file(str(self.dataset_dir / "dataset.parquet"))
            if digest != manifest["dataset_sha256"] or digest == self._attempted_digest:
                return
            self._attempted_digest = digest
            self.start()
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            with self._lock:
                if self._state["state"] != "running":
                    self._state = {"state": "failed", "error": str(exc), "serving_model_changed": False}

    def close(self) -> None:
        with self._lock:
            self._closed = True
            process = self._process
            thread = self._thread
            if process is not None and process.poll() is None:
                process.terminate()
        if thread is not None:
            thread.join(timeout=5)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if thread is not None:
            thread.join(timeout=5)


if __name__ == "__main__":
    manager = TrainingJobs()
    print(json.dumps(manager.start()))
    try:
        manager._thread.join()
    except KeyboardInterrupt:
        manager.close()
    print(json.dumps(manager.status(), indent=2))
    raise SystemExit(1 if manager.status()["state"] == "failed" else 0)
