import json
import time
from pathlib import Path

from agents.base import BaseAgent
from models.provider import OpenAI
from src.state import State, _num_suffix


class CoordinatorAgent(BaseAgent):

    extra_actions = ("check_status", "call_agent", "report")

    def __init__(
        self,
        sandbox=None,
        config_path=None,
        provider_cls=OpenAI,
        state: State | None = None,
        outputs_path="outputs",
        max_debate_rounds=3,
        max_pov_rounds=3,
    ):
        super().__init__(
            name="coordinator",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )
        self.config_path = config_path
        self.provider_cls = provider_cls
        self.state = state or State(outputs_path)
        self.repo_path = "/data" if sandbox else "."
        self.max_debate_rounds = int(max_debate_rounds)
        self.max_pov_rounds = int(max_pov_rounds)
        self.start_time = time.time()

        # Load A2A worker cards
        from agents import card_resolver
        self.resolver = card_resolver.CardResolver()
        self.cards = self.resolver.resolve_all()

    def execute(self, command, timeout=None):
        """Allow Coordinator read-only bash inspection across /outputs and /data."""
        cmd = str(command or "").strip()
        if any(tok in cmd for tok in (" >", ">>", "rm ", "mv ", "cp ", "sed -i", "tee ")):
            return 1, "Coordinator bash is read-only; do not modify files or artifacts directly."
        return super().execute(command, timeout=timeout)

    @staticmethod
    def _debate_trace(hyp: dict) -> str:
        hist = hyp.get("debate_history") or []
        if not hist:
            return ""
        parts = [
            f"R{h.get('round')}:{h.get('analyzer_verdict')}/{h.get('debator_decision')}"
            for h in hist
        ]
        return "[" + " -> ".join(parts) + "]"

    @staticmethod
    def _norm(name: str) -> str:
        return str(name or "").lower().replace(" ", "").replace("_", "").replace("-", "")

    def _container_path(self, host_path: str | Path) -> str:
        """Translate host outputs/ path to /outputs/... when running inside Docker sandbox."""
        if not self.sandbox:
            return str(host_path)
        p = Path(host_path).resolve()
        try:
            rel = p.relative_to(self.state.outputs_path.resolve()).as_posix()
            return f"/outputs/{rel}"
        except ValueError:
            return str(host_path)

    # --- State Supervision (Arasaka TaskQueue JSON) ---
    def check_status(self) -> dict:
        """Build Arasaka-style TaskQueue JSON summarizing all 4 phases."""
        sub_tasks = []
        any_pending = False
        any_failed = False

        # 1. Output Directory Structure
        struct_ok, issues = self.state.check_structure()
        if struct_ok:
            sub_tasks.append({
                "task_name": "Check Output Directory Structure",
                "status": "SUCCESS",
                "details": "The /outputs directory is properly structured (build, graph, hypothesis, pov, report, cache).",
            })
        else:
            any_failed = True
            sub_tasks.append({
                "task_name": "Check Output Directory Structure",
                "status": "FAILED",
                "details": f"Directory mismatch in /outputs: {issues}.",
            })

        # 2. Build Artifacts (Phase 1)
        build = self.state.get_build_status()
        b_status = str(build.get("status", "PENDING")).upper()
        if b_status == "READY":
            sub_tasks.append({
                "task_name": "Check Build Artifacts",
                "status": "SUCCESS",
                "details": f"Repository built at /outputs/build (language: {build.get('language', 'unknown')}, entry_type: {build.get('entry_type', 'cli')}).",
            })
        elif b_status == "FAILED":
            any_failed = True
            sub_tasks.append({
                "task_name": "Check Build Artifacts",
                "status": "FAILED",
                "details": "Build failed in /outputs/build/status.json. Fix or retry Repo Builder.",
            })
        else:
            any_pending = True
            sub_tasks.append({
                "task_name": "Check Build Artifacts",
                "status": "PENDING",
                "details": "Repository has not been built yet (/outputs/build/status.json missing or not READY). Dispatch repo-builder.",
            })

        # 3. Call Graph (Phase 2 input)
        cg_ok = self.state.call_graph_path().exists() and self.state.call_flows_path().exists()
        pending_files = self.state.pending_files()
        if cg_ok:
            top_preview = [f"{p['file']} ({p['flow_count']} flows, max_score={p['max_score']})" for p in pending_files[:10]]
            rem = max(0, len(pending_files) - len(top_preview))
            pending_note = f"Pending target files ({len(pending_files)} total): {top_preview}" + (f" (+{rem} more)" if rem else "")
            sub_tasks.append({
                "task_name": "Check Call Graph",
                "status": "SUCCESS",
                "details": f"call-graph.json & call-flows.jsonl ready. {pending_note}",
            })
        else:
            any_pending = True
            sub_tasks.append({
                "task_name": "Check Call Graph",
                "status": "PENDING",
                "details": "Static call-graph.json or call-flows.jsonl missing in /outputs/graph.",
            })

        # 4. Flows Retrieval (Phase 2 per chunk)
        chunks = self.state.get_chunks()
        if not chunks:
            any_pending = True
            sub_tasks.append({
                "task_name": "Check Flows Retrieval",
                "status": "PENDING",
                "details": "No chunk_xxx analyzed yet. Pick next target file from Check Call Graph and dispatch repo-retriever.",
            })
        else:
            for c in chunks:
                flow_ids = [f.get("id") for f in c["flows"] if f.get("id")]
                if c["retrieved"]:
                    sub_tasks.append({
                        "task_name": "Check Flows Retrieval",
                        "status": "SUCCESS",
                        "details": f"Chunk {c['chunk_id']} ({c['target_file']}) retrieved {len(flow_ids)} flows {flow_ids} -> {self._container_path(c['output_file'])}.",
                    })
                else:
                    any_pending = True
                    sub_tasks.append({
                        "task_name": "Check Flows Retrieval",
                        "status": "PENDING",
                        "details": f"Chunk {c['chunk_id']} ({c['target_file']}) waiting for repo-retriever -> {self._container_path(c['input_file'])}.",
                    })

        # 5. Hypothesis & Debate (Phase 3 per retrieved flow)
        approved, rejected = self.state.list_hypotheses()
        disputed = self.state.list_disputed_hypotheses()
        for c_id, flow in self.state.all_flows():
            fid = str(flow.get("id") or "")
            num = _num_suffix(fid)
            if num in approved:
                trace = self._debate_trace(approved[num])
                sub_tasks.append({
                    "task_name": "Check Hypothesis",
                    "status": "SUCCESS",
                    "details": f"{fid} ({c_id}) approved (VULNERABLE) -> /outputs/hypothesis/approved/hypothesis_{num}.json {trace}".strip(),
                })
            elif num in disputed:
                hyp = disputed[num]
                trace = self._debate_trace(hyp)
                owner = hyp.get("hypothesis_owner", "unknown")
                sub_tasks.append({
                    "task_name": "Check Hypothesis",
                    "status": "SUCCESS",
                    "details": f"{fid} ({c_id}) DISPUTED (owner={owner}) -> /outputs/hypothesis/disputed/hypothesis_{num}.json {trace}. Run PoV to arbitrate.".strip(),
                })
            elif num in rejected:
                trace = self._debate_trace(rejected[num])
                sub_tasks.append({
                    "task_name": "Check Hypothesis",
                    "status": "SUCCESS",
                    "details": f"{fid} ({c_id}) rejected -> /outputs/hypothesis/rejected/hypothesis_{num}.json {trace}".strip(),
                })
            else:
                any_pending = True
                sub_tasks.append({
                    "task_name": "Check Hypothesis",
                    "status": "PENDING",
                    "details": f"{fid} ({c_id}) not analyzed yet. Dispatch vuln-analyzer.",
                })

        # 6. PoV Verification & 7. Report (Phase 4 for APPROVED and DISPUTED flows)
        pov_results = self.state.list_pov_results()
        reports = {r["vuln_id"]: r for r in self.state.list_reports()}
        pov_candidates = {**approved, **disputed}
        for num, hyp in sorted(pov_candidates.items()):
            fid = str(hyp.get("flow_id") or f"flow_{num}")
            res = pov_results.get(num, {})
            p_status = str(res.get("status", "PENDING")).upper()
            in_disputed = num in disputed and num not in approved

            if p_status == "CONFIRMED":
                sub_tasks.append({
                    "task_name": "Check PoV",
                    "status": "SUCCESS",
                    "details": f"{fid} PoV CONFIRMED -> /outputs/pov/pov_{num}/result_{num}.json.",
                })
                vid = res.get("vuln_id")
                rep_ok = vid and vid in reports and reports[vid]["report_exists"] and reports[vid]["pov_exists"]
                if rep_ok:
                    sub_tasks.append({
                        "task_name": "Check Report",
                        "status": "SUCCESS",
                        "details": f"{fid} report exported -> /outputs/report/{vid}/report.md & pov.py.",
                    })
                else:
                    any_pending = True
                    sub_tasks.append({
                        "task_name": "Check Report",
                        "status": "PENDING",
                        "details": f"{fid} PoV is CONFIRMED but GitHub Advisory report is missing. Call report for {fid}.",
                    })
            elif p_status == "UNCONFIRMED":
                sub_tasks.append({
                    "task_name": "Check PoV",
                    "status": "SUCCESS",
                    "details": f"{fid} PoV UNCONFIRMED (not reproducible) -> /outputs/pov/pov_{num}/result_{num}.json.",
                })
            else:
                any_pending = True
                loc = "disputed" if in_disputed else "approved"
                label = "Disputed" if in_disputed else "Approved"
                sub_tasks.append({
                    "task_name": "Check PoV",
                    "status": "PENDING",
                    "details": f"{label} {fid} (/outputs/hypothesis/{loc}/hypothesis_{num}.json) not verified by PoV yet. Dispatch pov-generator.",
                })

        if any_failed:
            overall = "FAILED"
            summary = "Some critical tasks failed. Inspect failed sub_tasks and resolve them."
        elif any_pending or (pending_files and not chunks):
            overall = "PENDING"
            summary = "Some analysis tasks are not completed yet. Follow depth-first order (Build -> Retrieve -> Hypothesis/Debate -> PoV -> Report)."
        else:
            overall = "SUCCESS"
            summary = "All planned tasks completed."

        return {
            "main_task": "Repository-level vulnerability detection and validation",
            "overall_status": overall,
            "summary": summary,
            "sub_tasks": sub_tasks,
        }

    # --- Sub-loop Runners ---
    def _run_builder(self, task: str) -> str:
        from agents import RepoBuilderAgent
        agent = RepoBuilderAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)
        res = agent.run(
            self.repo_path,
            build_script=self._container_path(self.state.build_dir / "build.sh"),
            status_file=self._container_path(self.state.build_dir / "status.json"),
            task_hint=task,
        )
        return json.dumps({"agent": "repo-builder", "result": res}, ensure_ascii=False)

    def _run_retriever(self, args: dict) -> str:
        from agents import RepoRetrieverAgent
        agent = RepoRetrieverAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)
        flow_id = args.get("flow_id")
        target_file = args.get("target_file")
        task_hint = args.get("task", "")

        if flow_id:
            out_file, flow_obj = self.state.find_flow(flow_id)
            if not flow_obj:
                return json.dumps({"error": f"Flow {flow_id} not found in retrieved chunks."})
            updated = agent.stitch_flow(
                self.repo_path,
                flow_obj,
                output_file=out_file,
                call_graph_path=self._container_path(self.state.call_graph_path()),
                hint=task_hint,
            )
            return json.dumps({"agent": "repo-retriever", "mode": "stitch", "flow": updated}, ensure_ascii=False)

        if not target_file:
            pending = self.state.pending_files()
            if not pending:
                return json.dumps({"agent": "repo-retriever", "status": "NO_PENDING_FILES"})
            target_file = pending[0]["file"]

        chunk = self.state.create_chunk(target_file)
        if not chunk:
            return json.dumps({"error": f"No call-flows found for target_file: {target_file}"})

        flows = agent.run_chunk(
            self.repo_path,
            target_file=chunk["target_file"],
            chunk_input_path=self._container_path(chunk["input_file"]),
            chunk_output_path=self._container_path(chunk["output_file"]),
            call_graph_path=self._container_path(self.state.call_graph_path()),
            start_flow_idx=self.state.next_flow_index(),
            task_hint=task_hint,
        )
        return json.dumps({
            "agent": "repo-retriever",
            "chunk_id": chunk["chunk_id"],
            "target_file": chunk["target_file"],
            "retrieved_flows": [{"id": f.get("id"), "title": f.get("title"), "sink": f.get("sink")} for f in flows],
        }, ensure_ascii=False)

    def _run_analyze_debate(self, args: dict) -> str:
        from agents import VulnAnalyzerAgent, VulnDebatorAgent
        flow_id = args.get("flow_id")
        if not flow_id:
            return json.dumps({"error": "Missing required `flow_id` for vuln-analyzer."})

        _, flow_obj = self.state.find_flow(flow_id)
        if not flow_obj:
            return json.dumps({"error": f"Flow {flow_id} not found."})

        num = _num_suffix(flow_id)
        hyp_path = self.state.approved_dir / f"hypothesis_{num}.json"
        a_agent = VulnAnalyzerAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)
        d_agent = VulnDebatorAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)

        feedback = None
        last_hyp = None
        last_debate = None
        verdict = "BENIGN"
        decision = "REVISE"
        debate_history = []

        for round_idx in range(1, self.max_debate_rounds + 1):
            last_hyp = a_agent.run(
                self.repo_path,
                flow_obj,
                hypotheses=self._container_path(hyp_path),
                feedback=feedback,
            )
            if not isinstance(last_hyp, dict):
                break

            raw_v = str(last_hyp.get("verdict", "")).strip().upper()
            verdict = "VULNERABLE" if raw_v in ("VULN", "VULNERABLE") else "BENIGN"

            last_debate = d_agent.run(
                self.repo_path,
                flow_obj,
                last_hyp,
                defense=last_hyp if round_idx > 1 else None,
            )
            if not isinstance(last_debate, dict):
                break

            decision = str(last_debate.get("decision", "")).strip().upper()
            debate_history.append({
                "round": round_idx,
                "analyzer_verdict": verdict,
                "debator_decision": decision,
                "debator_reason": last_debate.get("reason", ""),
            })

            if decision == "ACCEPT":
                is_vuln = (verdict == "VULNERABLE")
                resolution = "CONSENSUS_VULNERABLE" if is_vuln else "CONSENSUS_BENIGN"
                payload = dict(last_hyp)
                payload["verdict"] = verdict
                payload["debate_consensus"] = last_debate.get("reason", "")
                payload["hypothesis_owner"] = "vuln-analyzer"
                payload["resolution"] = resolution
                payload["debate_history"] = debate_history
                saved = self.state.save_hypothesis(flow_id, payload, status="approved" if is_vuln else "rejected")
                return json.dumps({
                    "flow_id": flow_id,
                    "status": "APPROVED_FOR_POV" if is_vuln else "REJECTED",
                    "resolution": resolution,
                    "hypothesis_owner": "vuln-analyzer",
                    "analyzer_verdict": verdict,
                    "debator_decision": "ACCEPT",
                    "round": round_idx,
                    "saved_to": self._container_path(saved),
                    "summary": payload.get("title", payload.get("description", "")),
                    "debate_history": debate_history,
                }, ensure_ascii=False)

            feedback = last_debate

        # Exhausted debate rounds without ACCEPT -> escalating claiming side into disputed/ for PoV arbitration
        if isinstance(last_hyp, dict) and verdict == "VULNERABLE":
            payload = dict(last_hyp)
            payload["verdict"] = "VULNERABLE"
            payload["hypothesis_owner"] = "vuln-analyzer"
            payload["resolution"] = "DEADLOCK_ANALYZER_TO_POV"
            payload["debate_history"] = debate_history
            saved = self.state.save_hypothesis(flow_id, payload, status="disputed")
            return json.dumps({
                "flow_id": flow_id,
                "status": "DISPUTED",
                "resolution": "DEADLOCK_ANALYZER_TO_POV",
                "hypothesis_owner": "vuln-analyzer",
                "analyzer_verdict": verdict,
                "debator_decision": decision,
                "rounds": len(debate_history),
                "saved_to": self._container_path(saved),
                "summary": payload.get("title", payload.get("description", "")),
                "debate_history": debate_history,
                "next_action": f"Dispatch pov-generator with flow_id={flow_id} to verify empirically.",
            }, ensure_ascii=False)

        if isinstance(last_debate, dict) and verdict == "BENIGN" and decision == "REJECT":
            deb_hyp = last_debate.get("hypothesis") if isinstance(last_debate.get("hypothesis"), dict) else {}
            payload = {
                "id": deb_hyp.get("id") or flow_id,
                "verdict": "VULNERABLE",
                "cwe": deb_hyp.get("cwe") or [],
                "title": deb_hyp.get("title") or f"Debator challenge on {flow_obj.get('title', flow_id)}",
                "description": deb_hyp.get("description") or last_debate.get("reason", ""),
                "source": deb_hyp.get("source") or flow_obj.get("source", {}),
                "sink": deb_hyp.get("sink") or flow_obj.get("sink", {}),
                "flow": deb_hyp.get("flow") or {"chain": flow_obj.get("chain", [])},
                "preconditions": deb_hyp.get("preconditions") or [],
                "hint": deb_hyp.get("hint") or "; ".join(last_debate.get("suggestions") or []),
                "expected": deb_hyp.get("expected") or "",
                "oracle": deb_hyp.get("oracle") or {},
                "evidence": deb_hyp.get("evidence") or last_debate.get("evidence", []),
                "remediation": deb_hyp.get("remediation") or "",
                "hypothesis_owner": "vuln-debator",
                "resolution": "DEADLOCK_DEBATOR_TO_POV",
                "debate_history": debate_history,
            }
            saved = self.state.save_hypothesis(flow_id, payload, status="disputed")
            return json.dumps({
                "flow_id": flow_id,
                "status": "DISPUTED",
                "resolution": "DEADLOCK_DEBATOR_TO_POV",
                "hypothesis_owner": "vuln-debator",
                "analyzer_verdict": "BENIGN",
                "debator_decision": "REJECT",
                "rounds": len(debate_history),
                "saved_to": self._container_path(saved),
                "summary": payload.get("title", payload.get("description", "")),
                "debate_history": debate_history,
                "next_action": f"Dispatch pov-generator with flow_id={flow_id} to verify empirically.",
            }, ensure_ascii=False)

        payload = dict(last_hyp or {"id": flow_id, "verdict": "BENIGN"})
        payload["hypothesis_owner"] = "vuln-analyzer"
        payload["resolution"] = "DEADLOCK_REVISE_BENIGN"
        payload["debate_history"] = debate_history
        saved = self.state.save_hypothesis(flow_id, payload, status="rejected")
        return json.dumps({
            "flow_id": flow_id,
            "status": "REJECTED",
            "resolution": "DEADLOCK_REVISE_BENIGN",
            "hypothesis_owner": "vuln-analyzer",
            "analyzer_verdict": verdict,
            "debator_decision": decision,
            "rounds": len(debate_history),
            "saved_to": self._container_path(saved),
            "debate_history": debate_history,
        }, ensure_ascii=False)

    def _run_pov_subloop(self, args: dict) -> str:
        from agents import PovGeneratorAgent, PovVerifierAgent
        flow_id = args.get("flow_id")
        if not flow_id:
            return json.dumps({"error": "Missing required `flow_id` for pov-generator."})

        num = _num_suffix(flow_id)
        approved, _ = self.state.list_hypotheses()
        disputed = self.state.list_disputed_hypotheses()
        from_disputed = num in disputed and num not in approved
        hypothesis = approved.get(num) or disputed.get(num)
        if not hypothesis:
            return json.dumps({"error": f"No approved or disputed hypothesis found for {flow_id}."})

        script_path, result_path = self.state.pov_paths(flow_id)
        c_script = self._container_path(script_path)
        c_result = self._container_path(result_path)
        build_status = self.state.get_build_status()

        g_agent = PovGeneratorAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)
        v_agent = PovVerifierAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)

        feedback = None
        last_verdict = {}
        final_res = {}

        for attempt in range(1, self.max_pov_rounds + 1):
            gen_res = g_agent.run(
                self.repo_path,
                hypothesis,
                pov_script=c_script,
                pov_result=c_result,
                feedback=feedback,
                harness=self.state.harness,
                build_status=build_status,
            )
            exec_data = gen_res.get("res") if isinstance(gen_res, dict) and isinstance(gen_res.get("res"), dict) else {}

            verdict = v_agent.run(
                self.repo_path,
                hypothesis,
                pov_script=c_script,
                pov_result=exec_data or c_result,
            )
            if not isinstance(verdict, dict):
                verdict = {"decision": "UNCONFIRMED", "reason": "Verifier returned no verdict."}

            last_verdict = verdict
            decision = str(verdict.get("decision", "")).upper()
            final_res = {
                "flow_id": flow_id,
                "status": decision if decision in ("CONFIRMED", "UNCONFIRMED") else "RETRY",
                "attempts": attempt,
                "execution": exec_data,
                "verdict": verdict,
            }
            if decision in ("CONFIRMED", "UNCONFIRMED"):
                if decision == "CONFIRMED" and self.state.first_pov_sec is None:
                    self.state.first_pov_sec = time.time() - self.start_time
                result_path.write_text(json.dumps(final_res, indent=2, ensure_ascii=False), encoding="utf-8")
                promoted = self.state.promote_disputed(flow_id, approved=(decision == "CONFIRMED")) if from_disputed else None
                out = {
                    "flow_id": flow_id,
                    "status": decision,
                    "attempts": attempt,
                    "script_path": c_script,
                    "result_path": c_result,
                    "reason": verdict.get("reason", ""),
                    "evidence": verdict.get("evidence", ""),
                }
                if promoted:
                    out["promoted_to"] = self._container_path(promoted)
                return json.dumps(out, ensure_ascii=False)

            feedback = verdict

        final_res["status"] = "UNCONFIRMED"
        result_path.write_text(json.dumps(final_res, indent=2, ensure_ascii=False), encoding="utf-8")
        promoted = self.state.promote_disputed(flow_id, approved=False) if from_disputed else None
        out = {
            "flow_id": flow_id,
            "status": "UNCONFIRMED",
            "attempts": self.max_pov_rounds,
            "reason": last_verdict.get("reason", "PoV retries exhausted"),
        }
        if promoted:
            out["promoted_to"] = self._container_path(promoted)
        return json.dumps(out, ensure_ascii=False)

    # --- Action Handlers ---
    def _handle_action(self, action: str, payload: str) -> tuple[int, str]:
        if action == "check_status":
            return 0, json.dumps(self.check_status(), indent=2, ensure_ascii=False)

        args = self.extract_json(payload) if payload else None
        if not isinstance(args, dict):
            return 1, f"Invalid JSON payload for `{action}`."

        if action == "call_agent":
            target = self._norm(args.get("agent") or args.get("agent_name") or args.get("name"))
            if target in ("repobuilder", "builder", "repobuilderagent"):
                return 0, self._run_builder(args.get("task", ""))
            if target in ("reporetriever", "retriever", "reporetrieveragent"):
                return 0, self._run_retriever(args)
            if target in ("vulnanalyzer", "analyzer", "vulnanalyzeragent", "vulndebator", "debator", "vulndebatoragent"):
                return 0, self._run_analyze_debate(args)
            if target in ("povgenerator", "generator", "povgeneratoragent", "povverifier", "verifier", "povverifieragent"):
                return 0, self._run_pov_subloop(args)
            return 1, f"Unknown agent `{args.get('agent')}`. Valid keys: {list(self.cards.keys())}"

        if action == "report":
            flow_id = str(args.get("flow_id") or "")
            content = str(args.get("content") or "")
            num = _num_suffix(flow_id)
            script_path, result_path = self.state.pov_paths(flow_id)
            res = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
            if str(res.get("status", "")).upper() != "CONFIRMED":
                return 1, f"Cannot write report: {flow_id} PoV status is not CONFIRMED."

            vid = res.get("vuln_id") or self.state.next_vuln_id()
            ok, msg = self.state.save_report(content, script_path, vuln_id=vid)
            if not ok:
                return 1, msg
            res["vuln_id"] = vid
            result_path.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
            return 0, json.dumps({"status": "REPORT_SAVED", "vuln_id": vid, "path": f"/outputs/report/{vid}/report.md"})

        return 1, f"Unhandled action `{action}`."

    def run(self, repo=None):
        """Run Coordinator autonomous supervision loop until all tasks finish."""
        self.repo_path = str(repo or self.repo_path)
        self.memory.clear()
        self.step = 0
        self.cmd_history = []
        self.start_time = time.time()

        agents_desc = self.resolver.format_available_agents(self.cards)
        sys_prompt = self.render(self.system_prompt, available_agents=agents_desc)
        status_json = json.dumps(self.check_status(), indent=2, ensure_ascii=False)
        usr_prompt = self.render(
            self.user_prompt,
            repo=self.repo_path,
            initial_status=status_json,
        )

        self.messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": usr_prompt},
        ]

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            if extracted is None:
                extracted = {"status": "COMPLETED", "summary": thought}
            self.log_action("finish")
            self.log(thought=thought, action="finish", observation="Coordinator supervision finished")
            return True, extracted

        return self.loop(finish=finish, default={"status": "STOPPED"}, action_handler=self._handle_action)


__all__ = ["CoordinatorAgent"]
