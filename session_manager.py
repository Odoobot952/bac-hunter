"""
Loads "personas" (sets of auth material for different privilege levels/users)
from simple JSON files, e.g.:

    sessions/admin.json
    {
      "name": "admin",
      "headers": {
        "Cookie": "session=xyz-admin-token",
        "Authorization": "Bearer eyJ..."
      }
    }

    sessions/userA.json
    {
      "name": "userA",
      "headers": {
        "Cookie": "session=xyz-userA-token"
      }
    }

Keep real tokens out of git (see .gitignore in this project) -- these are
meant to be populated per-engagement, not committed.
"""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, field


@dataclass
class Persona:
    name: str
    headers: dict = field(default_factory=dict)


def load_persona(path: str) -> Persona:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    name = data.get("name") or os.path.splitext(os.path.basename(path))[0]
    return Persona(name=name, headers=data.get("headers", {}))


def load_personas_from_dir(dir_path: str) -> list[Persona]:
    personas = []
    for fname in sorted(os.listdir(dir_path)):
        if fname.endswith(".json"):
            personas.append(load_persona(os.path.join(dir_path, fname)))
    return personas


def apply_persona(headers: dict, persona: Persona) -> dict:
    """Return a copy of `headers` with the persona's auth headers merged in
    (persona values override the original request's values for matching keys)."""
    merged = dict(headers)
    merged.update(persona.headers)
    return merged
