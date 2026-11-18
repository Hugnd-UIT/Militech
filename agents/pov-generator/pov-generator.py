import json
import re
from agents.base import BaseAgent
from models.provider import OpenAI


# Format flow id to three digitss
def _num_suffix(flow_id):
    m = re.search(r"(\d+)$", str(flow_id or ""))
    return f"{int(m.group(1)):03d}" if m else str(flow_id or "001")


class PovGeneratorAgent(BaseAgent):
    def __init__(self, sandbox=None, config_path=None, provider_cls=OpenAI):
        
        # Initialize base agent
        super().__init__(
            name="pov-generator",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )

    def run(self, 
        repo, 
        hypothesis, 
        pov_script=None, 
        pov_result=None, 
        feedback=None,
        harness=None,
        build_status=None,
    ):
        flow_id = hypothesis.get("id") or hypothesis.get("flow_id") or "flow_001"
        num = _num_suffix(flow_id)
        pov_script = pov_script or f"/outputs/pov/pov_{num}/script_{num}.py"
        pov_result = pov_result or f"/outputs/pov/pov_{num}/result_{num}.json"
        if isinstance(feedback, dict):
            clean_ver = {
                "decision": feedback.get("decision", ""),
                "reason": feedback.get("reason", ""),
                "issues": feedback.get("issues", []),
                "suggestions": feedback.get("suggestions", []),
            }
            if feedback.get("evidence"):
                clean_ver["evidence"] = feedback.get("evidence")
            feedback_str = json.dumps(clean_ver, indent=2, ensure_ascii=False)
        elif feedback:
            feedback_str = json.dumps(feedback, indent=2, ensure_ascii=False) if not isinstance(feedback, str) else feedback
        else:
            feedback_str = ""

        self.cleanup_processes()

        # Feedback
        if self.messages and feedback:
            self.step = 0
            self.cmd_history = []
            obs = self.render(
                self.react_prompt,
                verifier=feedback_str,
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
            harness_str = json.dumps(harness, indent=2, ensure_ascii=False) if isinstance(harness, (dict, list)) else str(harness or "{}")
            
            # Build prompt
            initial_task = self.render(
                self.user_prompt,
                repo=str(repo),
                hypothesis=hyp_str,
                pov_script=pov_script,
                pov_result=pov_result,
                harness=harness_str,
            )
            
            if build_status:
                initial_task += f"\n\n### Build artifacts\n```json\n{json.dumps(build_status, indent=2, ensure_ascii=False)}\n```\n"
            
            self.messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": initial_task},
            ]

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            code, _ = self.execute(f"test -s {pov_script}")
            
            if not extracted and pov_result:
                _, content = self.execute(f"cat {pov_result} 2>/dev/null")
                if content:
                    extracted = self.extract_json(content)
            
            if (extracted and isinstance(extracted, dict)) or code == 0:
                self.log_action("finish")
                self.log(thought=thought, action="finish", observation="PoV generator completed")
                return True, extracted or True
            return False, None

        return self.loop(finish=finish, default=False)


__all__ = ["PovGeneratorAgent"]