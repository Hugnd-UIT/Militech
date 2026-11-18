import json
import re
import shutil
from pathlib import Path

from models import tracker
from src.dedup import rank_target_files


REQUIRED_REPORT_SECTIONS = (
    "### Summary",
    "### Details",
    "### PoC",
    "### Impact",
    "### Remediation",
)


def _num_suffix(flow_id: str) -> str:
    """Extract numeric suffix like '001' from 'flow_001' or return sanitized id."""
    m = re.search(r"(\d+)$", str(flow_id or ""))
    if m:
        return f"{int(m.group(1)):03d}"
    clean = re.sub(r"[^a-zA-Z0-9_-]", "_", str(flow_id or "001")).strip("_")
    return clean or "001"


class State:
    """Manages structured artifacts under outputs/ across all 4 pipeline phases."""

    def __init__(self, outputs_path="outputs"):
        self.outputs_path = Path(outputs_path).resolve()
        self.build_dir = self.outputs_path / "build"
        self.cache_dir = self.outputs_path / "cache"
        self.graph_dir = self.outputs_path / "graph"
        self.hypothesis_dir = self.outputs_path / "hypothesis"
        self.approved_dir = self.hypothesis_dir / "approved"
        self.rejected_dir = self.hypothesis_dir / "rejected"
        self.disputed_dir = self.hypothesis_dir / "disputed"
        self.pov_dir = self.outputs_path / "pov"
        self.report_dir = self.outputs_path / "report"

        self.harness = None
        self.first_pov_sec = None
        self.ensure_dirs()

    def to_container_path(self, path: str | Path) -> str:
        """Translate any path under outputs/ to /outputs/... for container execution."""
        p = Path(path).resolve()
        try:
            rel = p.relative_to(self.outputs_path.resolve()).as_posix()
            return f"/outputs/{rel}"
        except ValueError:
            return str(path)

    def ensure_dirs(self):
        """Create standard outputs/ directory layout cleanly."""
        for d in (
            self.build_dir,
            self.cache_dir,
            self.graph_dir,
            self.approved_dir,
            self.rejected_dir,
            self.disputed_dir,
            self.pov_dir,
            self.report_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

    def check_structure(self) -> tuple[bool, list[str]]:
        """Verify required directories exist and list any unexpected root entries."""
        expected = {"build", "cache", "graph", "hypothesis", "pov", "report"}
        missing = sorted(d for d in expected if not (self.outputs_path / d).is_dir())
        extra = sorted(
            p.name for p in self.outputs_path.iterdir()
            if p.name not in expected
        ) if self.outputs_path.exists() else []
        return (not missing and not extra), missing + extra

    # --- Phase 1: Build ---
    def get_build_status(self) -> dict:
        status_file = self.build_dir / "status.json"
        if not status_file.exists():
            return {"status": "PENDING"}
        try:
            data = json.loads(status_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {"status": "INVALID"}

    # --- Phase 2: Graph & Chunks ---
    def call_graph_path(self) -> Path:
        return self.graph_dir / "call-graph.json"

    def call_flows_path(self) -> Path:
        return self.graph_dir / "call-flows.jsonl"

    def get_chunks(self) -> list[dict]:
        """Inspect chunk_xxx directories and derive target_file + retrieved flows."""
        chunks = []
        if not self.graph_dir.exists():
            return chunks

        for cdir in sorted(self.graph_dir.glob("chunk_*"), key=lambda p: p.name):
            if not cdir.is_dir():
                continue
            num = _num_suffix(cdir.name)
            in_file = cdir / f"chunk-flow-{num}.jsonl"
            out_file = cdir / f"taint-flow-{num}.jsonl"

            target_file = None
            in_count = 0
            if in_file.exists():
                for line in in_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    in_count += 1
                    if target_file is None:
                        try:
                            obj = json.loads(line)
                            target_file = str(obj.get("dst", {}).get("file") or "").replace("\\", "/").strip().lstrip("/")
                        except Exception:
                            pass

            flows = []
            if out_file.exists():
                for line in out_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            flows.append(obj)
                    except Exception:
                        pass

            chunks.append({
                "chunk_id": cdir.name,
                "num": num,
                "target_file": target_file or "",
                "input_file": str(in_file),
                "output_file": str(out_file),
                "input_count": in_count,
                "retrieved": out_file.exists(),
                "flows": flows,
            })
        return chunks

    def next_chunk_num(self) -> str:
        existing = [int(_num_suffix(c["chunk_id"])) for c in self.get_chunks() if _num_suffix(c["chunk_id"]).isdigit()]
        return f"{(max(existing) + 1) if existing else 1:03d}"

    def next_flow_index(self) -> int:
        max_idx = 0
        for chunk in self.get_chunks():
            for flow in chunk["flows"]:
                m = re.search(r"(\d+)$", str(flow.get("id") or ""))
                if m:
                    max_idx = max(max_idx, int(m.group(1)))
        return max_idx + 1

    def pending_files(self) -> list[dict]:
        done = [c["target_file"] for c in self.get_chunks() if c["target_file"]]
        return rank_target_files(self.call_flows_path(), done_files=done)

    def create_chunk(self, target_file: str) -> dict | None:
        """Slice all call-flows matching target_file into chunk_xxx/chunk-flow-xxx.jsonl."""
        flows_file = self.call_flows_path()
        if not flows_file.exists():
            return None

        norm_target = str(target_file).replace("\\", "/").strip().lstrip("/")
        for existing in self.get_chunks():
            if existing["target_file"] == norm_target:
                return existing

        matched_lines = []
        for raw in flows_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            dst_f = str(obj.get("dst", {}).get("file") or "").replace("\\", "/").strip().lstrip("/")
            if dst_f == norm_target or dst_f.endswith(norm_target) or norm_target.endswith(dst_f):
                matched_lines.append(line)

        if not matched_lines:
            return None

        num = self.next_chunk_num()
        cdir = self.graph_dir / f"chunk_{num}"
        cdir.mkdir(parents=True, exist_ok=True)
        in_file = cdir / f"chunk-flow-{num}.jsonl"
        out_file = cdir / f"taint-flow-{num}.jsonl"
        in_file.write_text("\n".join(matched_lines) + "\n", encoding="utf-8")

        return {
            "chunk_id": cdir.name,
            "num": num,
            "target_file": norm_target,
            "input_file": str(in_file),
            "output_file": str(out_file),
            "input_count": len(matched_lines),
            "retrieved": out_file.exists(),
            "flows": [],
        }

    def all_flows(self) -> list[dict]:
        items = []
        for c in self.get_chunks():
            for flow in c["flows"]:
                items.append((c["chunk_id"], flow))
        return items

    def find_flow(self, flow_id: str) -> tuple[str | None, dict | None]:
        target_num = _num_suffix(flow_id)
        for c in self.get_chunks():
            for flow in c["flows"]:
                fid = str(flow.get("id") or "")
                if fid == flow_id or _num_suffix(fid) == target_num:
                    return c["output_file"], flow
        return None, None

    # --- Phase 3: Hypothesis & Debate ---
    def save_hypothesis(self, flow_id: str, data: dict, approved: bool | None = True, status: str | None = None) -> str:
        num = _num_suffix(flow_id)
        filename = f"hypothesis_{num}.json"
        bucket = status if status in ("approved", "rejected", "disputed") else ("approved" if approved else "rejected")
        dirs = {
            "approved": self.approved_dir,
            "rejected": self.rejected_dir,
            "disputed": self.disputed_dir,
        }
        dest_dir = dirs[bucket]
        dest_dir.mkdir(parents=True, exist_ok=True)

        for key, folder in dirs.items():
            if key != bucket:
                stale = folder / filename
                if stale.exists():
                    stale.unlink()

        dest_file = dest_dir / filename
        payload = dict(data)
        payload["flow_id"] = flow_id
        payload["decision"] = {"approved": "ACCEPT", "rejected": "REJECT", "disputed": "DISPUTED"}[bucket]
        dest_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(dest_file)

    @staticmethod
    def _scan_hypotheses(folder: Path) -> dict[str, dict]:
        res = {}
        if not folder.exists():
            return res
        for p in sorted(folder.glob("hypothesis_*.json")):
            try:
                res[_num_suffix(p.stem)] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
        return res

    def list_hypotheses(self) -> tuple[dict[str, dict], dict[str, dict]]:
        """Return (approved_map, rejected_map) keyed by numeric suffix '001'."""
        return self._scan_hypotheses(self.approved_dir), self._scan_hypotheses(self.rejected_dir)

    def list_disputed_hypotheses(self) -> dict[str, dict]:
        """Return disputed hypotheses awaiting empirical PoV arbitration."""
        return self._scan_hypotheses(self.disputed_dir)

    def promote_disputed(self, flow_id: str, approved: bool) -> str | None:
        """Move a disputed hypothesis into approved/ or rejected/ after PoV verification."""
        num = _num_suffix(flow_id)
        src = self.disputed_dir / f"hypothesis_{num}.json"
        if not src.exists():
            return None
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
        except Exception:
            data = {"flow_id": flow_id}
        data["pov_verified"] = "CONFIRMED" if approved else "UNCONFIRMED"
        return self.save_hypothesis(flow_id, data, status="approved" if approved else "rejected")

    # --- Phase 4: PoV & Report ---
    def pov_paths(self, flow_id: str) -> tuple[Path, Path]:
        num = _num_suffix(flow_id)
        pdir = self.pov_dir / f"pov_{num}"
        pdir.mkdir(parents=True, exist_ok=True)
        return pdir / f"script_{num}.py", pdir / f"result_{num}.json"

    def list_pov_results(self) -> dict[str, dict]:
        res = {}
        if not self.pov_dir.exists():
            return res
        for pdir in sorted(self.pov_dir.glob("pov_*")):
            if not pdir.is_dir():
                continue
            num = _num_suffix(pdir.name)
            rfile = pdir / f"result_{num}.json"
            if rfile.exists():
                try:
                    res[num] = json.loads(rfile.read_text(encoding="utf-8"))
                except Exception:
                    res[num] = {"status": "INVALID"}
            else:
                res[num] = {"status": "PENDING"}
        return res

    def next_vuln_id(self) -> str:
        existing = [
            int(_num_suffix(p.name))
            for p in self.report_dir.glob("vuln_*")
            if p.is_dir() and _num_suffix(p.name).isdigit()
        ]
        return f"vuln_{(max(existing) + 1) if existing else 1:03d}"

    def list_reports(self) -> list[dict]:
        reports = []
        if not self.report_dir.exists():
            return reports
        for vdir in sorted(self.report_dir.glob("vuln_*")):
            if not vdir.is_dir():
                continue
            md = vdir / "report.md"
            pov = vdir / "pov.py"
            reports.append({
                "vuln_id": vdir.name,
                "report_exists": md.exists() and md.stat().st_size > 0,
                "pov_exists": pov.exists() and pov.stat().st_size > 0,
            })
        return reports

    def save_report(self, markdown_content: str, pov_script_path: str | Path, vuln_id: str | None = None) -> tuple[bool, str]:
        """Validate required GitHub Advisory headings, copy pov.py, and write report.md."""
        missing = [sec for sec in REQUIRED_REPORT_SECTIONS if sec.lower() not in markdown_content.lower()]
        if missing:
            return False, f"Missing required sections: {', '.join(missing)}"

        src_pov = Path(pov_script_path)
        if not src_pov.exists():
            return False, f"PoV script not found: {src_pov}"

        vid = vuln_id or self.next_vuln_id()
        vdir = self.report_dir / vid
        vdir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(src_pov, vdir / "pov.py")
        (vdir / "report.md").write_text(markdown_content.strip() + "\n", encoding="utf-8")
        return True, str(vdir)

    # --- Metrics ---
    def save_metrics(self, elapsed_sec: float) -> str:
        """Write minimal QuotaTracker telemetry + elapsed timings to outputs/cache/metrics.json."""
        data = {"elapsed_sec": round(float(elapsed_sec), 2)}
        if self.first_pov_sec is not None:
            data["first_pov_sec"] = round(float(self.first_pov_sec), 2)
        data.update(tracker.tracker.summary())

        out = self.cache_dir / "metrics.json"
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return str(out)


__all__ = ["State", "REQUIRED_REPORT_SECTIONS"]
