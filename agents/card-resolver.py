from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Dict, List


@dataclass
class AgentSkill:
    id: str
    name: str
    description: str = ""
    examples: List[str] = field(default_factory=list)


@dataclass
class AgentCard:
    key: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    skills: List[AgentSkill] = field(default_factory=list)

    def to_prompt(self) -> str:
        lines = [
            f"- agent_key: `{self.key}` | name: {self.name}",
            f"  description: {self.description}",
            "  skills:",
        ]
        for s in self.skills:
            lines.append(f"    - {s.id} ({s.name}): {s.description}")
        return "\n".join(lines)


class CardResolver:
    def __init__(self, agents_dir: str | Path | None = None):
        self.agents_dir = Path(agents_dir) if agents_dir else Path(__file__).resolve().parent

    def load_card(self, card_path: Path, key: str) -> AgentCard:
        data = json.loads(card_path.read_text(encoding="utf-8"))
        skills = [
            AgentSkill(
                id=str(s.get("id", "")),
                name=str(s.get("name", "")),
                description=str(s.get("description", "")),
                examples=list(s.get("examples") or []),
            )
            for s in (data.get("skills") or [])
            if isinstance(s, dict)
        ]
        return AgentCard(
            key=key,
            name=str(data.get("name") or key),
            description=str(data.get("description") or ""),
            version=str(data.get("version") or "1.0.0"),
            skills=skills,
        )

    def resolve_card(self) -> Dict[str, AgentCard]:
        cards: Dict[str, AgentCard] = {}
        if not self.agents_dir.exists():
            return cards

        for entry in sorted(self.agents_dir.iterdir(), key=lambda p: p.name):
            if not entry.is_dir():
                continue
            card_path = entry / ".well-known" / "agent.json"
            if card_path.exists():
                cards[entry.name] = self.load_card(card_path, key=entry.name)
        return cards

    def get_agents(self, cards: Dict[str, AgentCard] | None = None) -> str:
        resolved = cards if cards is not None else self.resolve_card()
        if not resolved:
            return "No worker agents registered."
        return "\n".join(card.to_prompt() for card in resolved.values())


__all__ = ["AgentSkill", "AgentCard", "CardResolver"]