from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

from codesentinel.analysis_service import analyze_snapshot
from codesentinel.github_handler import RepositoryError, download_repository, parse_github_url
from codesentinel.models import AnalysisReport


load_dotenv()

app = FastAPI(
    title="CodeSentinel API",
    description="Read-only static auditing for public GitHub repositories.",
    version="1.0.0",
)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_url: str = Field(min_length=1, max_length=500)


@app.get("/health")
def health():
    return {"status": "ok", "service": "CodeSentinel"}


@app.post("/analyze", response_model=AnalysisReport)
def analyze(request: AnalyzeRequest):
    try:
        parse_github_url(request.repository_url)
        snapshot = download_repository(request.repository_url)
        return analyze_snapshot(snapshot)
    except RepositoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        # Do not expose source excerpts, request headers, or provider credentials in errors.
        raise HTTPException(
            status_code=500,
            detail="Analysis could not be completed. Try a smaller repository or review the local service setup.",
        ) from exc