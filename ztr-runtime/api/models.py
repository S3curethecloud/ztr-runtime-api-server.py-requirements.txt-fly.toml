from pydantic import BaseModel, ConfigDict

class TokenIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal: str
    intent: str
    scopes: list[str]
    ttl_seconds: int
    context: dict

class IntrospectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str

class TenantRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
