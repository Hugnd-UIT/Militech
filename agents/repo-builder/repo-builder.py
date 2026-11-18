import json
from pathlib import Path
from agents.base import BaseAgent
from models.provider import OpenAI


class RepoBuilderAgent(BaseAgent):
    def __init__(self, sandbox=None, config_path=None, provider_cls=OpenAI):
        
        # Initialize base agent
        super().__init__(
            name="repo-builder",
            sandbox=sandbox,
            config_path=config_path,
            provider_cls=provider_cls,
        )

    def manifest(self, repo_path):
        manifest_names = {
            "Makefile", "makefile", "GNUmakefile",
            "CMakeLists.txt", "configure.ac", "configure.in", "configure",
            "meson.build", "build.ninja", "build.sh",
            "package.json", "setup.py", "pyproject.toml", "requirements.txt",
            "Cargo.toml", "go.mod", "pom.xml", "build.gradle"
        }

        found = []
        if self.sandbox:
            code, out = self.execute(f"ls -a {repo_path}")
            if code == 0:
                for name in out.split():
                    if name in manifest_names:
                        found.append(name)
                return sorted(found)

        target = Path(repo_path).resolve()
        if target.exists():
            for item in target.iterdir():
                if item.name in manifest_names:
                    found.append(item.name)
        return sorted(found)

    def run(self, repo_path, build_script="/outputs/build/build.sh", status_file="/outputs/build/status.json", task_hint=None):
        # Reset memory
        self.memory.clear()
        self.step = 0
        self.cmd_history = []

        manifests = self.manifest(repo_path)

        # Build prompt
        initial_task = self.render(
            self.user_prompt,
            repo=str(repo_path),
            manifests=", ".join(manifests) if manifests else "none detected",
            build_script=str(build_script),
            status_file=str(status_file),
        )

        if task_hint:
            initial_task += f"\n\n## Note\n{task_hint}\n"

        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_task},
        ]

        def finish(thought, reply):
            extracted = self.extract_json(reply)
            if not extracted and status_file:
                _, raw = self.execute(f"cat {status_file} 2>/dev/null")
                if raw:
                    extracted = self.extract_json(raw)
                    
            if extracted and isinstance(extracted, dict):
                if self.sandbox and status_file:
                    payload = json.dumps(extracted, indent=2, ensure_ascii=False)
                    self.execute(f"mkdir -p $(dirname {status_file}) && cat << 'EOF' > {status_file}\n{payload}\nEOF")
                self.log_action("finish")
                self.log(thought=thought, action="finish", observation="Repo builder completed")
                return True, extracted
            
            return False, None

        return self.loop(finish=finish, default=False)

    # Explain why the target failed to build
    def explain(self):
        query = (
            "The repository build failed or could not be completed. "
            "Please explain concisely why the target failed to build, "
            "what specific errors or missing dependencies occurred, and "
            "what is needed to make it build successfully."
        )
        if not self.messages:
            self.messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": query},
            ]
        else:
            self.messages.append({"role": "user", "content": query})

        reply = self.call(self.messages)
        return reply


__all__ = ["RepoBuilderAgent"]