"""Custom exception types + FastAPI exception handlers."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

log = get_logger(__name__)


class AppError(Exception):
    """Base class for all deliberate errors."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    code: str = "internal_error"

    def __init__(self, message: str, *, detail: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_payload(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "detail": self.detail}


class AuthError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class ValidationAppError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "validation_error"


class ServiceUnavailableError(AppError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "service_unavailable"


class CryptoError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "crypto_error"


# --------------------------------------------------------------------------- #
# Handlers                                                                    #
# --------------------------------------------------------------------------- #


async def _app_error_handler(_: Request, exc: AppError) -> JSONResponse:  # noqa: RUF029
    log.warning("app_error", code=exc.code, message=exc.message, detail=exc.detail)
    return JSONResponse(status_code=exc.status_code, content=exc.to_payload())


async def _http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:  # noqa: RUF029
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": "http_error", "message": exc.detail, "detail": None},
    )


async def _validation_exception_handler(
    _: Request, exc: RequestValidationError
) -> JSONResponse:  # noqa: RUF029
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "code": "validation_error",
            "message": "Request validation failed",
            "detail": exc.errors(),
        },
    )


async def _unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:  # noqa: RUF029
    log.exception("unhandled_exception", error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"code": "internal_error", "message": "An unexpected error occurred"},
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)
    app.add_exception_handler(Exception, _unhandled_exception_handler)
