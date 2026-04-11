from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    url: str = Field(..., description="URL to score")


class ScoreResponse(BaseModel):
    url: str
    trust_score: int
    verdict: str
    predicted_class: str
    class_probabilities: dict
    risk: dict
    reasons: list[dict]
    feature_names: list[str]
