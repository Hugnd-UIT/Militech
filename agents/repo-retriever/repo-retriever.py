import json
from pathlib import Path
from agents.base import BaseAgent
from models.provider import OpenAI
from utils.skip import is_non_prod


class RepoRetrieverAgent(BaseAgent):
    def __init__(self, sandbox=None, config_path=None, provider_cls=OpenAI):
        
        # Initialize base agent
        super().__init__(
            name="repo-retriever",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )

    # Scan files
    def scan(self, repo_path):
        cmd = (
            f"find {repo_path} -type f "
            "-not -path '*/.*' "
            "-not -path '*/node_modules/*' "
            "-not -path '*/venv/*' "
            "-not -path '*/tests/*' "
            "-not -path '*/test/*' "
            "-not -path '*/examples/*' "
            "-not -path '*/example/*' "
            "-not -path '*/docs/*' "
            "-not -path '*/fixtures/*' "
            "-not -path '*/mock/*'"
        )
        code, out = self.execute(cmd)
        if code != 0:
            return []

        files = []
        for line in out.splitlines():
            clean = line.strip()
            if clean:
                rel = clean[len(repo_path):].lstrip("/")
                if not is_non_prod(rel):
                    files.append(rel)
        return sorted(files)

    # Load call graph
    def load_graph(self, graph_path=None):
        path_str = graph_path or "/outputs/call-graph.json"
        code, out = self.execute(f"cat {path_str} 2>/dev/null")
        if code == 0 and out.strip():
            try:
                return json.loads(out)
            except Exception:
                pass
        return {"nodes": [], "edges": []}

    # Normalize flow object to ensure consistency
    def _normalize_flow(self, obj, flow_id=None):
        if not isinstance(obj, dict) or not obj.get("sink") or not obj.get("source"):
            return None
        item = dict(obj)
        if flow_id:
            item["id"] = flow_id
        try:
            item["confidence"] = float(item.get("confidence") or 0.85)
        except Exception:
            item["confidence"] = 0.85
        sink = dict(item.get("sink") or {})
        if "function" in sink and "func" not in sink:
            sink["func"] = sink.pop("function")
        item["sink"] = sink
        return item

    # Read flows from file JSON or JSONL
    def _read_flows(self, path_str):
        _, raw = self.execute(f"cat {path_str} 2>/dev/null")
        if not raw or not raw.strip():
            return []
        raw = raw.strip()
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
        except Exception:
            pass
        parsed = []
        for l in raw.splitlines():
            l = l.strip()
            if l:
                try:
                    parsed.append(json.loads(l))
                except Exception:
                    pass
        return parsed

    def run(
        self,
        repo_path,
        target_file,
        chunk_input_path,
        chunk_output_path,
        call_graph_path="/outputs/graph/call-graph.json",
        start_flow_idx=1,
        task_hint=None,
    ):
        # Reset memory
        self.memory.clear()
        self.step = 0
        self.cmd_history = []

        self.execute(f"mkdir -p $(dirname {chunk_output_path}) && : > {chunk_output_path}")

        files_count = len(self.scan(repo_path))
        graph = self.load_graph(call_graph_path)

        # Build prompt
        initial_task = self.render(
            self.user_prompt,
            repo=str(repo_path),
            target=str(target_file),
            files=files_count,
            nodes=len(graph.get("nodes", [])),
            edges=len(graph.get("edges", [])),
            call_graph=str(call_graph_path),
            call_flows=str(chunk_input_path),
            taint_flows=str(chunk_output_path),
        )

        if task_hint:
            initial_task += f"\n\n## Note\n{task_hint}\n"

        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_task},
        ]

        collected = []

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            if not extracted:
                extracted = self._read_flows(chunk_output_path)
            
            if not extracted:
                return False, None
            
            items = extracted if isinstance(extracted, list) else [extracted]
            collected.clear()
            
            for x in items:
                norm = self._normalize_flow(x)
                if norm:
                    collected.append(norm)

            if not collected:
                return False, None

            self.log_action("finish")
            self.log(thought=thought, action="finish", observation=f"Chunk retrieval completed ({len(collected)} flows)")
            
            return True, True

        self.loop(finish=finish, default=True)
        if not collected:
            for x in self._read_flows(chunk_output_path):
                norm = self._normalize_flow(x)
                if norm:
                    collected.append(norm)

        # Deduplicate per sink inside chunk and assign global flow_xxx IDs
        from utils.dedup import dedup
        unique_flows = dedup(collected)
        final_flows = []
        for offset, flow in enumerate(unique_flows):
            flow["id"] = f"flow_{start_flow_idx + offset:03d}"
            final_flows.append(flow)

        payload = "\n".join(json.dumps(f, ensure_ascii=False) for f in final_flows)
        if payload:
            payload += "\n"

        self.execute(f"cat << 'EOF' > {chunk_output_path}\n{payload}EOF")

        self.log_thought(f"Chunk saved: {len(final_flows)} flows -> {chunk_output_path}")
        return final_flows

    # Deeply stitch indirect calls/function pointers for one specific flow.
    def stitch(self, repo_path, flow_obj, output_file, call_graph_path="/outputs/graph/call-graph.json", hint=""):
        # Reset memory
        self.memory.clear()
        self.step = 0
        self.cmd_history = []

        # Build prompt
        flow_str = json.dumps(flow_obj, indent=2, ensure_ascii=False)
        task = (
            f"## Task: Deep indirect call stitching\n"
            f"Repository: {repo_path}\n"
            f"Call graph: {call_graph_path}\n"
            f"Reason: {hint or 'Resolve missing function pointer, callback, or interface links in this trace.'}\n\n"
            f"### Current Flow\n```json\n{flow_str}\n```\n\n"
            f"Inspect source files on disk via `bash` to resolve the missing links from entry point to critical operation, "
            f"then output `finish` with the single updated JSON flow object (preserving `id`: `{flow_obj.get('id')}`)."
        )
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": task},
        ]

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            if isinstance(extracted, list) and extracted:
                extracted = extracted[0]
            norm = self._normalize_flow(extracted, flow_id=flow_obj.get("id"))
            if norm:
                self.log_action("finish")
                self.log(thought=thought, action="finish", observation=f"Stitched flow {norm['id']}")
                return True, norm
            return False, None

        updated = self.loop(finish=finish, default=flow_obj)
        if isinstance(updated, dict) and Path(output_file).exists():
            lines = []
            replaced = False
            
            for raw in Path(output_file).read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                try:
                    cur = json.loads(raw)
                    if cur.get("id") == updated.get("id"):
                        lines.append(json.dumps(updated, ensure_ascii=False))
                        replaced = True
                        continue
                except Exception:
                    pass
                lines.append(raw)
            
            if not replaced:
                lines.append(json.dumps(updated, ensure_ascii=False))
            Path(output_file).write_text("\n".join(lines) + "\n", encoding="utf-8")
        
        return updated


__all__ = ["RepoRetrieverAgent"]