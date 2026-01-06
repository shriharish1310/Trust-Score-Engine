from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import ScoreRequest, ScoreResponse
from .core.model import URLTrustModel

app = FastAPI(title="URL Trust Scorer", version="0.1")

# Allow Chrome extension (and local tools) to call the API during prototype stage
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # prototype: open CORS. Later: restrict to chrome-extension://<id>
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_model: URLTrustModel | None = None  # global variable that later becomes the model instance


@app.on_event("startup")
def load_model() -> None:
    global _model
    _model = URLTrustModel()  # create model instance once at server startup


# Check if server is running (sanity check)
@app.get("/health")
def health():
    return {"ok": True}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    if _model is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    return _model.score(req.url)
