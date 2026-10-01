from pydantic import BaseModel
from typing import Any


class ApiResponse(BaseModel):
    code: int = 0
    message: str = "ok"
    data: Any = None


def success(data: Any = None, message: str = "ok") -> dict:
    return ApiResponse(code=0, message=message, data=data).model_dump()
