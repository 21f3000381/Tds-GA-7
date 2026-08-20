"""HTTP service for the CI/CD container release gate."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from policy import evaluate

app = FastAPI(title="CI/CD Container Release Gate")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health():
    return {"ok": True, "endpoint": "/release-gate"}


@app.post("/release-gate")
@app.post("/release-gate/")
async def release_gate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"decision": "block", "violations": []})
    if not isinstance(payload, dict):
        return JSONResponse({"decision": "block", "violations": []})
    return JSONResponse(evaluate(payload))
