import json
from agents.base import BaseAgent
from models.provider import OpenAI


class VulnDebatorAgent(BaseAgent):
    """Adversarial critic agent challenging analyzer hypotheses with code evidence."""

    def __init__(self, sandbox=None, config_path=None, provider_cls=OpenAI):
        super().__init__(
            name="vuln-debator",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )

    def run(self, repo, taint_flow, hypothesis, defense=None):
        """Evaluate or counter a candidate vulnerability hypothesis using disk evidence."""
        hyp_str = json.dumps(hypothesis, indent=2, ensure_ascii=False) if isinstance(hypothesis, (dict, list)) else str(hypothesis or "")
        flow_str = json.dumps(taint_flow, indent=2, ensure_ascii=False) if isinstance(taint_flow, (dict, list)) else str(taint_flow or "")
        def_str = json.dumps(defense, indent=2, ensure_ascii=False) if isinstance(defense, (dict, list)) else str(defense or "")

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
            self.memory.clear()
            self.step = 0
            self.cmd_history = []
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
                ev = extracted.get("evidence")
                if decision in ("ACCEPT", "REJECT", "REVISE") and isinstance(ev, list) and len(ev) > 0:
                    extracted["decision"] = decision
                    self.log_action("finish")
                    self.log(thought=thought, action="finish", observation=f"Debate decision: {decision}")
                    return True, extracted
            return False, None

        return self.loop(finish=finish, default=False)


__all__ = ["VulnDebatorAgent"]
