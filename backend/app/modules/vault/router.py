"""Vault API routes."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_user
from app.models import AuditLog, User
from app.modules.vault import schemas
from app.modules.vault.models import VaultAccessGrant, VaultObject
from app.modules.vault.services import encryption, storage
from app.services.audit import audit_logger

router = APIRouter(prefix="/vault", tags=["vault"])


@router.post("/files", response_model=schemas.VaultObjectOut, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit=Depends(audit_logger),
) -> Any:
    payload = await file.read()
    blob = encryption.encrypt_for_user(payload, user.id)

    object_id = uuid.uuid4()
    storage_path = storage.write_blob(user.id, object_id, blob.ciphertext)

    obj = VaultObject(
        id=object_id,
        owner_id=user.id,
        name=file.filename or "untitled",
        size=len(payload),
        mime_type=file.content_type or "application/octet-stream",
        storage_path=storage_path,
        nonce=blob.nonce,
        wrapped_dek=blob.wrapped_dek,
        dek_nonce=blob.dek_nonce,
    )
    db.add(obj)
    await db.commit()
    await db.refresh(obj)

    await audit.append(
        actor_id=user.id,
        action="vault.upload",
        resource_type="vault.object",
        resource_id=str(obj.id),
        metadata={"name": obj.name, "size": obj.size},
    )

    return schemas.VaultObjectOut(
        id=obj.id, name=obj.name, size=obj.size, mime_type=obj.mime_type, created_at=obj.created_at
    )


@router.get("/files", response_model=list[schemas.VaultObjectOut])
async def list_files(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> Any:
    rows = (
        await db.execute(
            select(VaultObject)
            .where(VaultObject.owner_id == user.id)
            .order_by(VaultObject.created_at.desc())
        )
    ).scalars().all()
    return [
        schemas.VaultObjectOut(
            id=r.id, name=r.name, size=r.size, mime_type=r.mime_type, created_at=r.created_at
        )
        for r in rows
    ]


@router.get("/files/{object_id}/download")
async def download_file(
    object_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit=Depends(audit_logger),
) -> StreamingResponse:
    obj = (
        await db.execute(select(VaultObject).where(VaultObject.id == object_id))
    ).scalar_one_or_none()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    is_owner = obj.owner_id == user.id
    if not is_owner:
        grant = (
            await db.execute(
                select(VaultAccessGrant).where(
                    VaultAccessGrant.object_id == object_id,
                    VaultAccessGrant.grantee_id == user.id,
                )
            )
        ).scalar_one_or_none()
        if not grant:
            raise HTTPException(status_code=403, detail="No access")

    ciphertext = storage.read_blob(obj.storage_path)
    plaintext = encryption.decrypt_for_user(
        user_id=obj.owner_id,
        ciphertext=ciphertext,
        nonce=obj.nonce,
        wrapped_dek=obj.wrapped_dek,
        dek_nonce=obj.dek_nonce,
    )

    await audit.append(
        actor_id=user.id,
        action="vault.download",
        resource_type="vault.object",
        resource_id=str(obj.id),
        metadata={"name": obj.name, "by": str(user.id)},
    )

    def _iter():
        yield plaintext

    return StreamingResponse(
        _iter(),
        media_type=obj.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{obj.name}"'},
    )


@router.delete("/files/{object_id}")
async def delete_file(
    object_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit=Depends(audit_logger),
) -> Response:
    obj = (
        await db.execute(select(VaultObject).where(VaultObject.id == object_id))
    ).scalar_one_or_none()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Owner only")

    storage.delete_blob(obj.storage_path)
    await db.delete(obj)
    await audit.append(
        actor_id=user.id,
        action="vault.delete",
        resource_type="vault.object",
        resource_id=str(object_id),
        metadata={"name": obj.name},
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/files/{object_id}/share", response_model=schemas.GrantOut, status_code=201)
async def share_file(
    object_id: uuid.UUID,
    payload: schemas.ShareRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    audit=Depends(audit_logger),
) -> Any:
    obj = (
        await db.execute(select(VaultObject).where(VaultObject.id == object_id))
    ).scalar_one_or_none()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    if obj.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Owner only")

    grant = VaultAccessGrant(
        object_id=object_id,
        grantee_id=payload.grantee_id,
        expires_at=payload.expires_at,
        permissions=payload.permissions,
    )
    db.add(grant)
    await db.commit()
    await db.refresh(grant)

    await audit.append(
        actor_id=user.id,
        action="vault.share",
        resource_type="vault.object",
        resource_id=str(object_id),
        metadata={"grantee": str(payload.grantee_id), "permissions": payload.permissions},
    )
    return schemas.GrantOut(
        id=grant.id,
        object_id=grant.object_id,
        grantee_id=grant.grantee_id,
        created_at=grant.created_at,
        expires_at=grant.expires_at,
        permissions=grant.permissions,
    )


@router.get("/audit", response_model=list[schemas.AuditEntryOut])
async def list_audit(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> Any:
    rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.resource_type.like("vault.%"))
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        schemas.AuditEntryOut(
            id=r.id,
            timestamp=r.timestamp,
            actor_id=r.actor_id,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            metadata=r.metadata_json or {},
            entry_hash=r.entry_hash.hex() if isinstance(r.entry_hash, (bytes, bytearray)) else str(r.entry_hash),
        )
        for r in rows
    ]
