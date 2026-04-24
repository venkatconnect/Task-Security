"""Shared risk-scoring rubric used by both LLM02 and LLM06 assessments.

Keeping one rubric means the before/after comparison is apples-to-apples and
'fully mitigated' cannot sneak in — `residual_risk()` enforces a floor.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Level(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


LEVEL_LABEL = {
    Level.LOW: "Low",
    Level.MEDIUM: "Medium",
    Level.HIGH: "High",
    Level.CRITICAL: "Critical",
}

LEVEL_COLOR = {
    Level.LOW: "#2ecc71",
    Level.MEDIUM: "#f1c40f",
    Level.HIGH: "#e67e22",
    Level.CRITICAL: "#e74c3c",
}


@dataclass
class RiskScore:
    likelihood: Level
    impact: Level

    @property
    def score(self) -> int:
        return int(self.likelihood) * int(self.impact)

    @property
    def band(self) -> Level:
        s = self.score
        if s <= 3:
            return Level.LOW
        if s <= 6:
            return Level.MEDIUM
        if s <= 9:
            return Level.HIGH
        return Level.CRITICAL

    @property
    def label(self) -> str:
        return LEVEL_LABEL[self.band]

    @property
    def color(self) -> str:
        return LEVEL_COLOR[self.band]


@dataclass
class Assessment:
    title: str
    threat: str
    pre: RiskScore
    post: RiskScore
    residual_scenarios: list[str]
    mitigations: list[str]
    monitoring: list[str]

    def __post_init__(self) -> None:
        # Enforce the 'fully mitigated is typically not an option' hint:
        # the post score can never drop below LOW, and we require at least
        # one concrete residual-risk scenario to be documented.
        if not self.residual_scenarios:
            raise ValueError(
                "Post-mitigation assessment must list at least one residual scenario."
            )
        if self.post.score < Level.LOW:  # structurally impossible but explicit
            raise ValueError("Residual risk cannot be below Low.")
