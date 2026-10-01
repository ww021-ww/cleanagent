from typing import Any

from pydantic import BaseModel, Field


class ReviewDecisionRequest(BaseModel):
    reviewer: str = Field(min_length=1)
    note: str = ""
    corrected_fields: dict[str, Any] = Field(default_factory=dict)
