import json
import re
import time

from agents.base import BaseAgent
from models.provider import OpenAI
from src.state import State, _num_suffix


class CoordinatorAgent(BaseAgent):

    extra_actions = ("call_agent", "report")

    def __init__(
        self,
        sandbox=None,
        config_path=None,
        provider_cls=OpenAI,
        state: State | None = None,
        outputs_path="outputs",
        max_debate_rounds=3,
        max_exploit_rounds=3,
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
        self.max_exploit_rounds = int(max_exploit_rounds)
        self.start_time = time.time()

        # Load A2A worker cards
        from agents import card_resolver
        self.resolver = card_resolver.CardResolver()
        self.cards = self.resolver.resolve_card()

    def execute(self, command, timeout=None):
        """
        The coordinator has read-only access
        """
        cmd = str(command or "").strip()
        if any(tok in cmd for tok in (" >", ">>", "rm ", "mv ", "cp ", "sed -i", "tee ")):
            return 1, "Coordinator bash is read-only; do not modify files or artifacts directly."
        return super().execute(command, timeout=timeout)

    def render(self, template, **kwargs):
        if template == self.react_prompt and "status" not in kwargs:
            kwargs["status"] = json.dumps(self.check_status(), indent=2, ensure_ascii=False)
        return super().render(template, **kwargs)

    # Status-checking tool for coordinators
    def check_status(self) -> dict:
        sub_tasks = []
        any_pending = False
        any_failed = False

        # Check output directory structure
        struct_ok, issues = self.state.check_structure()
        if struct_ok:
            sub_tasks.append({
                "task_name": "Check outputs directory",
                "status": "SUCCESS",
                "details": "The /outputs directory is properly structured.",
            })
        else:
            any_failed = True
            sub_tasks.append({
                "task_name": "Check outputs directory",
                "status": "FAILED",
                "details": f"Directory mismatch in /outputs: {issues}.",
            })

        # Check build artifacts
        build = self.state.get_build_status()
        b_status = str(build.get("status", "PENDING")).upper()
        if b_status == "READY":
            sub_tasks.append({
                "task_name": "Check build artifacts",
                "status": "SUCCESS",
                "details": f"Repository built at /outputs/build successfully.",
            })
        elif b_status == "FAILED":
            any_failed = True
            reason = str(build.get("reason", "")).strip()
            details = f"Build failed in /outputs/build/status.json: {reason} Fix or retry Repo Builder." if reason else "Build failed in /outputs/build/status.json. Fix or retry Repo Builder."
            sub_tasks.append({
                "task_name": "Check build artifacts",
                "status": "FAILED",
                "details": details,
            })
        else:
            any_pending = True
            sub_tasks.append({
                "task_name": "Check build artifacts",
                "status": "PENDING",
                "details": "Repository has not been built yet. Dispatch repo-builder.",
            })

        # Check hypothesis & unanalyzed flows
        approved, rejected = self.state.list_hypotheses()
        disputed = self.state.list_disputed_hypotheses()
        all_flows = self.state.all_flows()
        has_unanalyzed_flows = any(
            _num_suffix(flow.get("id") or "") not in approved
            and _num_suffix(flow.get("id") or "") not in disputed
            and _num_suffix(flow.get("id") or "") not in rejected
            for _, flow in all_flows
        )

        # Check target files
        pending_targets = self.state.pending_files()
        if pending_targets:
            any_pending = True
            next_f = pending_targets[0]["file"]
            if has_unanalyzed_flows:
                sub_tasks.append({
                    "task_name": "Check target files",
                    "status": "WAITING",
                    "details": f"{len(pending_targets)} target files pending retrieval (next: {next_f}), but active chunk has unanalyzed flows. Complete Phase 3-5 for active flows before retrieving next file.",
                })
            else:
                sub_tasks.append({
                    "task_name": "Check target files",
                    "status": "PENDING",
                    "details": f"{len(pending_targets)} target files pending retrieval. Next: {next_f}.",
                })
        else:
            sub_tasks.append({
                "task_name": "Check target files",
                "status": "SUCCESS",
                "details": "All target files have been sliced into chunks.",
            })

        # Check flows retrieval
        chunks = self.state.get_chunks()
        if not chunks:
            any_pending = True
            sub_tasks.append({
                "task_name": "Check flows retrieval",
                "status": "PENDING",
                "details": "No chunk analyzed yet. Dispatch repo-retriever to retrieve candidate flows.",
            })
        else:
            for c in chunks:
                flow_ids = [f.get("id") for f in c["flows"] if f.get("id")]
                if c["retrieved"]:
                    sub_tasks.append({
                        "task_name": "Check flows retrieval",
                        "status": "SUCCESS",
                        "details": f"Chunk {c['chunk_id']} ({c['target_file']}) retrieved {len(flow_ids)} flows {flow_ids}.",
                    })
                else:
                    any_pending = True
                    sub_tasks.append({
                        "task_name": "Check flows retrieval",
                        "status": "PENDING",
                        "details": f"Chunk {c['chunk_id']} ({c['target_file']}) waiting for repo-retriever.",
                    })

        # Check hypothesis
        for c_id, flow in all_flows:
            fid = str(flow.get("id") or "")
            num = _num_suffix(fid)
            if num in approved:
                sub_tasks.append({
                    "task_name": "Check hypothesis",
                    "status": "SUCCESS",
                    "details": f"{fid} ({c_id}) VULNERABLE",
                })
            elif num in disputed:
                sub_tasks.append({
                    "task_name": "Check hypothesis",
                    "status": "SUCCESS",
                    "details": f"{fid} ({c_id}) DISPUTED. Run PoV to arbitrate.",
                })
            elif num in rejected:
                sub_tasks.append({
                    "task_name": "Check hypothesis",
                    "status": "SUCCESS",
                    "details": f"{fid} ({c_id}) BENIGN",
                })
            else:
                any_pending = True
                sub_tasks.append({
                    "task_name": "Check hypothesis",
                    "status": "PENDING",
                    "details": f"{fid} ({c_id}) not analyzed yet. Dispatch vuln-analyzer.",
                })

        # Check PoV
        pov_results = self.state.list_pov_results()
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
                    "details": f"{fid} PoV CONFIRMED.",
                })
            elif p_status == "UNCONFIRMED":
                sub_tasks.append({
                    "task_name": "Check PoV",
                    "status": "SUCCESS",
                    "details": f"{fid} PoV UNCONFIRMED.",
                })
            else:
                any_pending = True
                label = "Disputed" if in_disputed else "Approved"
                sub_tasks.append({
                    "task_name": "Check PoV",
                    "status": "PENDING",
                    "details": f"{label} {fid} hypothesis {num} not verified by PoV yet. Dispatch pov-generator.",
                })

        # Check report
        reports = {r["vuln_id"]: r for r in self.state.list_reports()}
        for num, hyp in sorted(pov_candidates.items()):
            res = pov_results.get(num, {})
            p_status = str(res.get("status", "PENDING")).upper()
            if p_status == "CONFIRMED":
                fid = str(hyp.get("flow_id") or f"flow_{num}")
                vid = res.get("vuln_id")
                rep_ok = vid and vid in reports and reports[vid]["report_exists"] and reports[vid]["pov_exists"]
                if rep_ok:
                    sub_tasks.append({
                        "task_name": "Check report",
                        "status": "SUCCESS",
                        "details": f"{fid} report exported.",
                    })
                else:
                    any_pending = True
                    sub_tasks.append({
                        "task_name": "Check report",
                        "status": "PENDING",
                        "details": f"{fid} PoV is CONFIRMED but report is missing. Call report for {fid}.",
                    })
            elif p_status == "UNCONFIRMED":
                fid = str(hyp.get("flow_id") or f"flow_{num}")
                sub_tasks.append({
                    "task_name": "Check report",
                    "status": "SKIPPED",
                    "details": f"{fid} PoV is UNCONFIRMED. Vulnerability not confirmed, do not author report.",
                })

        if any_failed:
            overall = "FAILED"
            summary = "Some critical tasks failed. Inspect failed sub tasks and resolve them."
        elif any_pending:
            overall = "PENDING"
            summary = "Some analysis tasks are not completed yet. Follow depth-first order build -> retrieve -> hypothesis -> PoV -> report."
        else:
            overall = "SUCCESS"
            summary = "All planned tasks completed."

        return {
            "main_task": "Repository-level vulnerability detection and validation",
            "overall_status": overall,
            "summary": summary,
            "sub_tasks": sub_tasks,
        }

    # Call builder
    def _run_builder(self, task: str) -> str:
        from agents import RepoBuilderAgent
        agent = RepoBuilderAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)
        status_file = self.state.build_dir / "status.json"
        res = agent.run(
            self.repo_path,
            build_script=self.state.to_container_path(self.state.build_dir / "build.sh"),
            status_file=self.state.to_container_path(status_file),
            task_hint=task,
        )
        build_status = self.state.get_build_status()
        b_status = str(build_status.get("status", "")).upper() if isinstance(build_status, dict) else ""
        r_status = str(res.get("status", "")).upper() if isinstance(res, dict) else ""

        is_failed = not res or r_status == "FAILED" or b_status == "FAILED" or (r_status != "READY" and b_status != "READY")
        out = {"agent": "repo-builder", "result": res}

        if is_failed:
            explanation = agent.explain()
            if explanation:
                out["explanation"] = explanation
                if status_file.exists():
                    try:
                        cur_st = json.loads(status_file.read_text(encoding="utf-8"))
                        if isinstance(cur_st, dict) and not cur_st.get("reason"):
                            cur_st["reason"] = explanation
                            status_file.write_text(json.dumps(cur_st, indent=2, ensure_ascii=False), encoding="utf-8")
                    except Exception:
                        pass

        return json.dumps(out, ensure_ascii=False)

    # Call retriever
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
            updated = agent.stitch(
                self.repo_path,
                flow_obj,
                output_file=out_file,
                call_graph_path=self.state.to_container_path(self.state.call_graph_path()),
                hint=task_hint,
            )
            return json.dumps({"agent": "repo-retriever", "mode": "stitch", "flow": updated}, ensure_ascii=False)

        if not target_file:
            pending = self.state.pending_files()
            if not pending:
                return json.dumps({"agent": "repo-retriever", "status": "NO PENDING FILES"})
            target_file = pending[0]["file"]

        chunk = self.state.create_chunk(target_file)
        if not chunk:
            return json.dumps({"error": f"No call-flows found for target file: {target_file}"})

        flows = agent.run(
            self.repo_path,
            target_file=chunk["target_file"],
            chunk_input_path=self.state.to_container_path(chunk["input_file"]),
            chunk_output_path=self.state.to_container_path(chunk["output_file"]),
            call_graph_path=self.state.to_container_path(self.state.call_graph_path()),
            start_flow_idx=self.state.next_flow_index(),
            task_hint=task_hint,
        )
        return json.dumps({
            "agent": "repo-retriever",
            "chunk_id": chunk["chunk_id"],
            "target_file": chunk["target_file"],
            "retrieved_flows": [{"id": f.get("id"), "title": f.get("title"), "sink": f.get("sink")} for f in flows],
        }, ensure_ascii=False)

    # Call vuln-analyzer and vuln-debator
    def _run_static_analysis(self, args: dict) -> str:
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
        last_round = 1

        # Debate rounds
        for round_idx in range(1, self.max_debate_rounds + 1):
            last_round = round_idx
            last_hyp = a_agent.run(
                self.repo_path,
                flow_obj,
                hypotheses=self.state.to_container_path(hyp_path),
                feedback=feedback,
            )
            if not isinstance(last_hyp, dict):
                break

            raw_v = str(last_hyp.get("verdict", "")).strip().upper()
            verdict = "VULNERABLE" if raw_v == "VULNERABLE" else "BENIGN"

            last_debate = d_agent.run(
                self.repo_path,
                flow_obj,
                last_hyp,
                defense=last_hyp if round_idx > 1 else None,
            )
            if not isinstance(last_debate, dict):
                break

            decision = str(last_debate.get("decision", "")).strip().upper()

            if decision == "ACCEPT":
                is_vuln = (verdict == "VULNERABLE")
                consensus_text = last_debate.get("reason", "")
                payload = dict(last_hyp)
                payload["verdict"] = verdict
                payload["consensus"] = consensus_text
                saved = self.state.save_hypothesis(flow_id, payload, status="approved" if is_vuln else "rejected")
                return json.dumps({
                    "flow_id": flow_id,
                    "status": "APPROVED" if is_vuln else "REJECTED",
                    "round": round_idx,
                    "saved": self.state.to_container_path(saved),
                    "summary": payload.get("title", payload.get("description", "")),
                    "consensus": consensus_text,
                }, ensure_ascii=False)

            feedback = last_debate

        # Exhausted debate rounds
        consensus_text = (last_debate or {}).get("reason", "") if isinstance(last_debate, dict) else ""

        target_hyp = None
        if verdict == "VULNERABLE":
            target_hyp = last_hyp
        elif decision == "REJECT" and isinstance(last_debate, dict):
            target_hyp = last_debate.get("hypothesis") if isinstance(last_debate.get("hypothesis"), dict) else last_debate

        if target_hyp and isinstance(target_hyp, dict) and target_hyp.get("verdict") == "VULNERABLE":
            payload = dict(target_hyp)
            payload["consensus"] = consensus_text
            saved = self.state.save_hypothesis(flow_id, payload, status="disputed")
            return json.dumps({
                "flow_id": flow_id,
                "status": "DISPUTED",
                "round": last_round,
                "saved": self.state.to_container_path(saved),
                "summary": payload.get("title", payload.get("description", "")),
                "consensus": consensus_text,
                "next_action": f"Dispatch pov-generator with flow id={flow_id} to verify empirically.",
            }, ensure_ascii=False)

        # Neither side established a vulnerability hypothesis
        payload = dict(last_hyp or {"id": flow_id, "verdict": "BENIGN"})
        payload["verdict"] = "BENIGN"
        payload["consensus"] = consensus_text
        saved = self.state.save_hypothesis(flow_id, payload, status="rejected")
        return json.dumps({
            "flow_id": flow_id,
            "status": "REJECTED",
            "round": last_round,
            "saved": self.state.to_container_path(saved),
            "summary": payload.get("title", payload.get("description", "")),
            "consensus": consensus_text,
        }, ensure_ascii=False)

    # Call pov-generator and pov-verifier
    def _run_dynamic_analysis(self, args: dict) -> str:
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
        c_script = self.state.to_container_path(script_path)
        c_result = self.state.to_container_path(result_path)
        build_status = self.state.get_build_status()

        g_agent = PovGeneratorAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)
        v_agent = PovVerifierAgent(sandbox=self.sandbox, config_path=self.config_path, provider_cls=self.provider_cls)

        feedback = None
        last_verdict = {}
        final_res = {}

        for attempt in range(1, self.max_exploit_rounds + 1):
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
                    out["promoted_to"] = self.state.to_container_path(promoted)
                return json.dumps(out, ensure_ascii=False)

            feedback = verdict

        final_res["status"] = "UNCONFIRMED"
        result_path.write_text(json.dumps(final_res, indent=2, ensure_ascii=False), encoding="utf-8")
        promoted = self.state.promote_disputed(flow_id, approved=False) if from_disputed else None
        out = {
            "flow_id": flow_id,
            "status": "UNCONFIRMED",
            "attempts": self.max_exploit_rounds,
            "reason": last_verdict.get("reason", "Exploit retries exhausted"),
        }
        if promoted:
            out["promoted_to"] = self.state.to_container_path(promoted)
        return json.dumps(out, ensure_ascii=False)

    # Handle coordinator action
    def _handle_action(self, action: str, payload: str) -> tuple[int, str]:
        if action == "report":
            if not payload or not payload.strip():
                return 1, "Empty report payload."

            m = re.search(r"^\s*flow_id:\s*(flow_\w+|\d+)", payload, re.IGNORECASE | re.MULTILINE)
            if not m:
                return 1, "Missing `flow_id: flow_xxx` header in report action."
            flow_id = m.group(1).strip()
            if not flow_id.startswith("flow_") and flow_id.isdigit():
                flow_id = f"flow_{int(flow_id):03d}"

            content = re.sub(r"^\s*flow_id:\s*[^\n]+\n*", "", payload, flags=re.IGNORECASE).strip()
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
            return 0, json.dumps({"status": "REPORT SAVED", "vuln_id": vid, "path": f"/outputs/report/{vid}/report.md"})

        args = self.extract_json(payload) if payload else None
        if not isinstance(args, dict):
            return 1, f"Invalid JSON payload for `{action}`."

        # Call agent
        if action == "call_agent":
            target = str(args.get("agent") or "").strip().lower().replace("_", "-")
            valid_agents = ["repo-builder", "repo-retriever", "vuln-analyzer", "vuln-debator", "pov-generator", "pov-verifier"]
            if target == "repo-builder":
                return 0, self._run_builder(args.get("task", ""))
            if target == "repo-retriever":
                return 0, self._run_retriever(args)
            if target in ("vuln-analyzer", "vuln-debator"):
                return 0, self._run_static_analysis(args)
            if target in ("pov-generator", "pov-verifier"):
                return 0, self._run_dynamic_analysis(args)
            return 1, f"Unknown agent `{args.get('agent')}`. Valid agents: {valid_agents}"

        return 1, f"Unhandled action `{action}`."

    def run(self, repo=None):
        self.repo_path = str(repo or self.repo_path)

        # Reset memory
        self.memory.clear()
        self.step = 0
        self.cmd_history = []
        self.start_time = time.time()

        # Build prompt
        agents_desc = self.resolver.get_agents(self.cards)
        sys_prompt = self.render(self.system_prompt, available_agents=agents_desc)
        status_json = json.dumps(self.check_status(), indent=2, ensure_ascii=False)
        usr_prompt = self.render(
            self.user_prompt,
            repo=self.repo_path,
            status=status_json,
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
            self.log(thought=thought, action="finish", observation="Coordinator finished")
            return True, extracted

        return self.loop(finish=finish, default={"status": "STOPPED"}, action_handler=self._handle_action)


__all__ = ["CoordinatorAgent"]