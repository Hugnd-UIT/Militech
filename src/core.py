import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from docker.sandbox import LocalSandbox
from src.state import State
from utils.logger import setup_logger


def _is_git_url(target: str) -> bool:
    s = str(target or "").strip()
    if s.startswith(("http://", "https://", "ssh://", "git://", "git@")):
        return True
    return s.endswith(".git") and not Path(s).exists()


def _repo_name(target: str) -> str:
    s = str(target or "").strip().rstrip("/\\")
    if _is_git_url(s):
        name = s.split("/")[-1].split(":")[-1]
        return name[:-4] if name.endswith(".git") else (name or "target")
    return Path(s).resolve().name or "target"


def _clear_dir(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        return
    for entry in path.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def _prepare_repo(repo_arg: str, branch: str | None = None, in_container: bool = False) -> Path:
    raw = str(repo_arg).strip()
    if _is_git_url(raw):
        if not in_container:
            raise RuntimeError("Git URL targets must run inside Docker (use run.sh or --in-container).")
        dest = Path("/data")
        _clear_dir(dest)
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([raw, str(dest)])
        subprocess.run(cmd, check=True)
        return dest

    src = Path(raw).resolve()
    if in_container and src == Path("/host_repo") and src != Path("/data"):
        dest = Path("/data")
        _clear_dir(dest)
        shutil.copytree(src, dest, dirs_exist_ok=True, symlinks=True)
        return dest
    return src


class Militech:
    """Entry-point orchestrator initializing sandbox, graphify, and the Master Coordinator."""

    def __init__(
        self,
        repo_path,
        outputs_path="outputs",
        config_path=None,
        provider_cls=None,
        branch=None,
        in_container=None,
    ):
        self.in_container = Path("/.dockerenv").exists() if in_container is None else bool(in_container)
        self.repo_label = _repo_name(repo_path)
        self.repo = _prepare_repo(repo_path, branch=branch, in_container=self.in_container)

        base_outputs = Path(outputs_path).resolve()
        if self.in_container or base_outputs.name == self.repo_label:
            self.outputs_path = base_outputs
        else:
            self.outputs_path = base_outputs / self.repo_label

        self.config_path = config_path
        self.state = State(self.outputs_path)
        self.log = setup_logger(log_file=self.state.cache_dir / "agents.log")

        if provider_cls is None:
            from models.provider import OpenAI
            self.provider_cls = OpenAI
        else:
            self.provider_cls = provider_cls

        self.repo_container = "/data"
        self.outputs_container = "/outputs"
        self.container = None

    def init_sandbox(self):
        """Initialize execution sandbox (local subprocess in container, or Docker from host)."""
        if self.in_container:
            self.container = LocalSandbox()
        else:
            from docker.sandbox import init as sandbox_init
            self.container = sandbox_init(repo_path=str(self.repo), outputs_path=str(self.outputs_path))
        self.log.info(f"{self.container.name} [{self.container.status}]")
        return self.container

    def phase_graph(self):
        """Run graphify AST call-graph extraction and filter raw call-flows."""
        self.log.info("=== Static Graph Extraction ===")
        graph_out = self.state.call_graph_path()
        flows_out = self.state.call_flows_path()

        try:
            import graphify
            graphify.callgraph(str(self.repo), str(graph_out), flow=str(flows_out))
            if flows_out.exists():
                from src.dedup import filter as filter_flows
                raw_lines = flows_out.read_text(encoding="utf-8").splitlines()
                cleaned = filter_flows(raw_lines)
                payload = "\n".join(json.dumps(x, ensure_ascii=False) for x in cleaned)
                flows_out.write_text((payload + "\n") if payload else "", encoding="utf-8")
        except Exception as e:
            self.log.warning(f"Graphify: {e}")

        try:
            import importlib
            fuzz_mod = importlib.import_module("src.fuzz-harness")
            self.state.harness = fuzz_mod.check(self.repo, self.state.cache_dir)
        except Exception as e:
            self.log.warning(f"Fuzz harness check: {e}")

    def run(self):
        """Initialize environment and hand control over to CoordinatorAgent."""
        start = time.time()
        self.init_sandbox()
        self.phase_graph()

        from agents import CoordinatorAgent
        coordinator = CoordinatorAgent(
            sandbox=self.container,
            config_path=self.config_path,
            provider_cls=self.provider_cls,
            state=self.state,
            outputs_path=self.outputs_path,
        )

        coord_result = None
        try:
            self.log.info("=== Coordinator Supervision ===")
            coord_result = coordinator.run(repo=self.repo_container)
        finally:
            elapsed = time.time() - start
            metrics_path = self.state.save_metrics(elapsed)
            self.log.info(f"Metrics saved to {metrics_path}")

        reports = self.state.list_reports()
        self.log.info(f"\nCompleted in {elapsed:.1f}s | Confirmed reports: {len(reports)}")
        return {
            "coordinator": coord_result,
            "reports": reports,
            "elapsed_sec": round(elapsed, 2),
        }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Militech")
    parser.add_argument("repo", help="Path or Git URL of target repository")
    parser.add_argument("--branch", default=None, help="Git branch/tag when cloning URL target")
    parser.add_argument("--outputs", default="outputs", help="Path to outputs directory")
    parser.add_argument("--config", default=None, help="Path to config.yml")
    parser.add_argument("--provider", default="openai", choices=["openai", "anthropic"], help="LLM provider")
    parser.add_argument("--in-container", dest="in_container", action="store_true", default=None, help="Run directly inside container without docker-py")
    args = parser.parse_args()

    if args.provider == "anthropic":
        from models.provider import Anthropic
        provider_cls = Anthropic
    else:
        from models.provider import OpenAI
        provider_cls = OpenAI

    app = Militech(
        repo_path=args.repo,
        outputs_path=args.outputs,
        config_path=args.config,
        provider_cls=provider_cls,
        branch=args.branch,
        in_container=args.in_container,
    )
    res = app.run()

    confirmed = len(res.get("reports", []))
    color = "\033[1;32m" if confirmed > 0 else "\033[1;33m"
    print(f"\n{color}[+] Done. Confirmed vulnerabilities: {confirmed}\033[0m")


if __name__ == "__main__":
    main()


__all__ = ["Militech", "main"]
