"""Reusable schemas: pagination + standardized error envelope."""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Page(BaseModel):
    """Pagination query parameters."""

    page: int = Field(1, ge=1, description="1-indexed page number")
    size: int = Field(50, ge=1, le=500, description="Page size (max 500)")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.size

    @property
    def limit(self) -> int:
        return self.size


class Paginated(BaseModel, Generic[T]):
    items: list[T]
    page: int
    size: int
    total: int

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ErrorResponse(BaseModel):
    code: str
    message: str
    detail: Any | None = None


class StatusResponse(BaseModel):
    status: str = "ok"
    detail: dict[str, Any] | None = None
