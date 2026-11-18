import json
from agents.base import BaseAgent
from models.provider import OpenAI


class VulnDebatorAgent(BaseAgent):
    def __init__(self, sandbox=None, config_path=None, provider_cls=OpenAI):

        # Initialize base agent
        super().__init__(
            name="vuln-debator",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )

    def run(self, repo, taint_flow, hypothesis, defense=None):
        hyp_str = json.dumps(hypothesis, indent=2, ensure_ascii=False) if isinstance(hypothesis, (dict, list)) else str(hypothesis or "")
        flow_str = json.dumps(taint_flow, indent=2, ensure_ascii=False) if isinstance(taint_flow, (dict, list)) else str(taint_flow or "")
        if isinstance(defense, dict):
            clean_def = {
                "verdict": defense.get("verdict", ""),
                "defense": defense.get("defense", ""),
                "evidence": defense.get("evidence", []),
            }
            for k in ("id", "title", "description", "sink", "oracle"):
                if defense.get(k):
                    clean_def[k] = defense[k]
            def_str = json.dumps(clean_def, indent=2, ensure_ascii=False)
        elif defense:
            def_str = json.dumps(defense, indent=2, ensure_ascii=False) if not isinstance(defense, str) else defense
        else:
            def_str = ""

        if self.messages and defense:
            self.step = 0
            self.cmd_history = []
            obs = self.render(
                self.react_prompt,
                analyzer=def_str,
                code=0,
                output="",
            )
            self.messages.append({"role": "user", "content": obs})
        else:
            # Reset memory
            self.memory.clear()
            self.step = 0
            self.cmd_history = []

            # Build prompt
            initial_task = self.render(
                self.user_prompt,
                repo=str(repo),
                hypothesis=hyp_str,
                taint_flow=flow_str,
            )
            self.messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": initial_task},
            ]

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            if extracted and isinstance(extracted, dict):
                decision = str(extracted.get("decision", "")).strip().upper()
                verdict = str(extracted.get("verdict", "")).strip().upper()
                ev = extracted.get("evidence")

                # Review schema with decision
                if decision in ("ACCEPT", "REJECT", "REVISE") and isinstance(ev, list) and len(ev) > 0:
                    extracted["decision"] = decision
                    self.log_action("finish")
                    self.log(thought=thought, action="finish", observation=f"Debate decision: {decision}")
                    return True, extracted
                
                # Full hypothesis schema with verdict
                if verdict in ("VULNERABLE", "BENIGN") and isinstance(ev, list) and len(ev) > 0:
                    norm_v = "VULNERABLE" if verdict == "VULNERABLE" else "BENIGN"
                    extracted["verdict"] = norm_v
                    extracted["decision"] = "REJECT" if norm_v == "VULNERABLE" else "ACCEPT"
                    self.log_action("finish")
                    self.log(thought=thought, action="finish", observation=f"Debate overturn hypothesis: {norm_v}")
                    return True, extracted
            return False, None

        return self.loop(finish=finish, default=False)


__all__ = ["VulnDebatorAgent"]