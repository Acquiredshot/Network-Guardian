from typing import Any, Literal
from pydantic import BaseModel

ErrorCode = Literal["VALIDATION_ERROR", "BAD_REQUEST", "NOT_FOUND", "CONFLICT", "INTERNAL_ERROR"]

class ErrorBody(BaseModel):
    code: ErrorCode
    message: str
    details: Any = None

class ErrorResponse(BaseModel):
    error: ErrorBody
