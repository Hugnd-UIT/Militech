import json
import re
from agents.base import BaseAgent
from models.provider import OpenAI


def _num_suffix(flow_id):
    m = re.search(r"(\d+)$", str(flow_id or ""))
    return f"{int(m.group(1)):03d}" if m else str(flow_id or "001")


class PovVerifierAgent(BaseAgent):
    def __init__(self, sandbox=None, config_path=None, provider_cls=OpenAI):
        
        # Initialize base agent
        super().__init__(
            name="pov-verifier",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )

    def run(self, 
        repo, 
        hypothesis, 
        pov_script=None, 
        pov_result=None
    ):
        flow_id = hypothesis.get("id") or hypothesis.get("flow_id") or "flow_001"
        num = _num_suffix(flow_id)
        pov_script = pov_script or f"/outputs/pov/pov_{num}/script_{num}.py"
        default_result_path = f"/outputs/pov/pov_{num}/result_{num}.json"
        
        if pov_result is None:
            pov_result = default_result_path
        if isinstance(pov_result, dict):
            clean_gen = {
                "status": pov_result.get("status", ""),
                "exit_code": pov_result.get("exit_code", 0),
                "error_type": pov_result.get("error_type"),
                "output": pov_result.get("output", ""),
            }
            pov_str = json.dumps(clean_gen, indent=2, ensure_ascii=False)
        elif pov_result:
            pov_str = json.dumps(pov_result, indent=2, ensure_ascii=False) if not isinstance(pov_result, str) else pov_result
        else:
            pov_str = ""

        self.cleanup_processes()

        # Feedback
        if self.messages and pov_result:
            self.step = 0
            self.cmd_history = []
            obs = self.render(
                self.react_prompt,
                generator=pov_str,
                code=0,
                output="",
            )
            self.messages.append({"role": "user", "content": obs})
        else:
            # Reset memory
            self.memory.clear()
            self.step = 0
            self.cmd_history = []
            
            hyp_str = json.dumps(hypothesis, indent=2, ensure_ascii=False) if isinstance(hypothesis, (dict, list)) else str(hypothesis or "")
            
            # Build prompt
            initial_task = self.render(
                self.user_prompt,
                repo=str(repo),
                hypothesis=hyp_str,
                pov_script=pov_script,
                pov_result=pov_str,
            )

            self.messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": initial_task},
            ]

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            if extracted and isinstance(extracted, dict):
                dec = str(extracted.get("decision", "")).strip().upper()

                if not dec and extracted.get("issues"):
                    dec = "RETRY"
                
                if dec in ("CONFIRMED", "UNCONFIRMED", "RETRY"):
                    extracted["decision"] = dec
                    self.log_action("finish")
                    self.log(thought=thought, action="finish", observation=f"PoV verifier: {dec}")
                    return True, extracted

            return False, None

        return self.loop(finish=finish, default=False)


__all__ = ["PovVerifierAgent"]