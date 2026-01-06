from pydantic import BaseModel, HttpUrl, Field


class ScoreRequest(BaseModel):
    url: str = Field(..., description="URL to score")


class ScoreResponse(BaseModel):
    url: str
    trust_score: int
    verdict: str
    risk: dict
    reasons: list[dict]
    feature_names: list[str]
