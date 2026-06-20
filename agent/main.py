"""AgentCore Runtime HTTP protocol contract: host 0.0.0.0:8080,
POST /invocations, GET /ping. See:
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-http-protocol-contract.html
"""

import time

from fastapi import FastAPI
from pydantic import BaseModel

from strands_agent import build_agent

app = FastAPI()
_agent = None


def _get_agent():
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent


class InvocationRequest(BaseModel):
    prompt: str


@app.post("/invocations")
def invoke(request: InvocationRequest) -> dict:
    result = _get_agent()(request.prompt)
    return {"response": str(result), "status": "success"}


@app.get("/ping")
def ping() -> dict:
    return {"status": "Healthy", "time_of_last_update": int(time.time())}
