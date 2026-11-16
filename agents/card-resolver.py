from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Dict, List


@dataclass
class AgentSkill:
    """Single capability entry from an agent's A2A card."""

    id: str
    name: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


@dataclass
class AgentCard:
    """Parsed A2A agent card loaded from .well-known/agent.json."""

    key: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    skills: List[AgentSkill] = field(default_factory=list)

    def to_prompt(self) -> str:
        """Format compact capability description for Coordinator injection."""
        lines = [
            f"- agent_key: `{self.key}` | name: {self.name}",
            f"  description: {self.description}",
            "  skills:",
        ]
        for s in self.skills:
            tags_str = ", ".join(s.tags)
            lines.append(f"    - {s.id} ({s.name}): {s.description} [tags: {tags_str}]")
        return "\n".join(lines)


class CardResolver:
    """Discovers and resolves A2A agent cards under the agents directory."""

    def __init__(self, agents_dir: str | Path | None = None):
        self.agents_dir = Path(agents_dir) if agents_dir else Path(__file__).resolve().parent

    def load_card(self, card_path: Path, key: str) -> AgentCard:
        """Load and parse a single .well-known/agent.json file."""
        data = json.loads(card_path.read_text(encoding="utf-8"))
        skills = [
            AgentSkill(
                id=str(s.get("id", "")),
                name=str(s.get("name", "")),
                description=str(s.get("description", "")),
                tags=list(s.get("tags") or []),
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

    def resolve_all(self) -> Dict[str, AgentCard]:
        """Resolve all worker agent cards sorted alphabetically by folder name."""
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

    def format_available_agents(self, cards: Dict[str, AgentCard] | None = None) -> str:
        """Render resolved worker cards as a clean prompt block."""
        resolved = cards if cards is not None else self.resolve_all()
        if not resolved:
            return "No worker agents registered."
        return "\n".join(card.to_prompt() for card in resolved.values())


__all__ = ["AgentSkill", "AgentCard", "CardResolver"]
