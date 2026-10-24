"""Chunked media transfers with bounded memory and atomic downloads."""
from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import os
import tempfile
from pathlib import Path
from collections.abc import Awaitable, Callable
from typing import Any

from .client import Message, random_id
from .errors import UnsupportedFeature
from .tl import TLObject, functions, types

PART_SIZE = 512 * 1024
MAX_WORKERS = 16


def worker_count(client, workers: int | None) -> int:
    count = client.transfer_workers if workers is None else workers
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_WORKERS:
        raise ValueError(f"workers must be an integer between 1 and {MAX_WORKERS}")
    return count


async def _finish(future: asyncio.Future) -> Any:
    """Defer cancellation until disk I/O or child-task cleanup has really ended."""
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(future)
            break
        except asyncio.CancelledError:
            if future.cancelled():
                raise
            cancelled = True
        except BaseException:
            if cancelled:
                raise asyncio.CancelledError from None
            raise
    if cancelled:
        raise asyncio.CancelledError
    return result


async def _disk(function: Callable, *args) -> Any:
    # Cancelling to_thread alone leaves a live thread using a closing file handle.
    return await _finish(asyncio.create_task(asyncio.to_thread(function, *args)))


async def _parallel(*operations: Awaitable) -> None:
    tasks = [asyncio.create_task(operation, name="easyproto-transfer") for operation in operations]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await _finish(asyncio.gather(*tasks, return_exceptions=True))


def _file_version(stream) -> tuple:
    info = os.fstat(stream.fileno())
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


async def upload(client, path: str | Path, *, workers: int | None = None) -> TLObject:
    concurrency = worker_count(client, workers)
    path = Path(path)
    with path.open("rb") as stream:
        version = _file_version(stream)
        size = version[0]
        if not size:
            raise ValueError("Cannot upload an empty file")
        file_id = random_id()
        parts = (size + PART_SIZE - 1) // PART_SIZE
        concurrency = min(concurrency, parts)
        big = size > 10 * 1024 * 1024
        digest = None if big else hashlib.md5()
        queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency)

        async def produce():
            for index in range(parts):
                chunk = await _disk(stream.read, PART_SIZE)
                if len(chunk) != min(PART_SIZE, size - index * PART_SIZE):
                    raise OSError("Upload source changed during reading")
                if digest is not None:
                    digest.update(chunk)  # Always in file order, regardless of RPC completion.
                await queue.put((index, chunk))
            if await _disk(stream.read, 1):
                raise OSError("Upload source grew during reading")
            for _ in range(concurrency):
                await queue.put(None)

        async def consume():
            while (item := await queue.get()) is not None:
                index, chunk = item
                fields = dict(file_id=file_id, file_part=index, bytes=chunk)
                if big:
                    fields["file_total_parts"] = parts
                result = await client.invoke(TLObject("upload.saveBigFilePart" if big else "upload.saveFilePart", **fields))
                if result is not True:
                    raise OSError("Telegram did not accept the uploaded part")

        await _parallel(produce(), *(consume() for _ in range(concurrency)))
        if _file_version(stream) != version:
            raise OSError("Upload source changed during transfer")
    if big:
        return types.inputFileBig(id=file_id, parts=parts, name=path.name)
    return types.inputFile(id=file_id, parts=parts, name=path.name, md5_checksum=digest.hexdigest())


async def uploaded_media(client, path, as_photo: bool, workers: int | None) -> TLObject:
    uploaded = await upload(client, path, workers=workers)
    if as_photo:
        return types.inputMediaUploadedPhoto(file=uploaded)
    return types.inputMediaUploadedDocument(file=uploaded,
        mime_type=mimetypes.guess_type(str(path))[0] or "application/octet-stream",
        attributes=[types.documentAttributeFilename(file_name=Path(path).name)])


async def send_media(client, target, path, *, caption: str = "", as_photo: bool = False,
                     workers: int | None = None, **options):
    worker_count(client, workers)
    peer = await client.resolve(target)
    if isinstance(path, (str, Path)):
        result = await client.invoke(functions.messages.sendMedia(peer=peer,
            media=await uploaded_media(client, path, as_photo, workers), message=caption, random_id=random_id(), **options))
        return client._message(result, target, caption)
    paths = list(path)
    if not 2 <= len(paths) <= 10:
        raise ValueError("Albums require 2–10 files")
    album = []
    for index, item in enumerate(paths):
        uploaded = await client.invoke(functions.messages.uploadMedia(peer=peer, media=await uploaded_media(client, item, as_photo, workers)))
        if uploaded.name == "messageMediaPhoto":
            photo = uploaded.photo
            value = types.inputMediaPhoto(id=types.inputPhoto(id=photo.id, access_hash=photo.access_hash, file_reference=photo.file_reference))
        elif uploaded.name == "messageMediaDocument":
            doc = uploaded.document
            value = types.inputMediaDocument(id=types.inputDocument(id=doc.id, access_hash=doc.access_hash, file_reference=doc.file_reference))
        else:
            raise UnsupportedFeature(f"Cannot add {uploaded.name} to an album")
        album.append(types.inputSingleMedia(media=value, random_id=random_id(), message=caption if index == 0 else ""))
    return await client.invoke(functions.messages.sendMultiMedia(peer=peer, multi_media=album, **options))


def _write_at(stream, offset: int, data: bytes) -> None:
    stream.seek(offset)
    remaining = memoryview(data)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise OSError("Could not write downloaded data")
        remaining = remaining[written:]


async def download(client, message: Message | TLObject, destination: str | Path = ".", *,
                   workers: int | None = None) -> Path:
    concurrency = worker_count(client, workers)
    raw = message.raw if isinstance(message, Message) else message
    media = raw.get("media", raw)
    if not isinstance(media, TLObject):
        raise ValueError("Message has no downloadable media")
    if media.name == "messageMediaDocument" and media.get("document"):
        doc = media.document
        location = types.inputDocumentFileLocation(id=doc.id, access_hash=doc.access_hash,
                                                   file_reference=doc.file_reference, thumb_size="")
        name = next((a.file_name for a in doc.attributes if a.name == "documentAttributeFilename"), f"{doc.id}.bin")
        size, dc_id = doc.size, doc.dc_id
    elif media.name == "messageMediaPhoto" and media.get("photo"):
        photo = media.photo
        sizes = [s for s in photo.sizes if s.name in ("photoSize", "photoSizeProgressive")]
        if not sizes:
            raise UnsupportedFeature("Photo has no downloadable size")
        def photo_size(value):
            return value.get("size", max(value.get("sizes", [0])))
        largest = max(sizes, key=photo_size)
        location = types.inputPhotoFileLocation(id=photo.id, access_hash=photo.access_hash,
            file_reference=photo.file_reference, thumb_size=largest.type)
        size, dc_id, name = photo_size(largest), photo.dc_id, f"{photo.id}.jpg"
    else:
        raise UnsupportedFeature("Only document and photo downloads are implemented")
    if not isinstance(size, int) or size < 0:
        raise ValueError("Invalid media size")
    requested = str(destination)
    destination = Path(destination)
    if destination.is_dir() or requested.endswith(os.sep):
        destination = destination / Path(name.replace("\\", "/")).name
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".easyproto-download-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.truncate(size)
        if size:
            async with client._at_dc(dc_id) as connection:
                offsets = iter(range(0, size, PART_SIZE))

                async def receive():
                    # Separate handles avoid shared seek positions on every platform.
                    with open(temporary, "r+b", buffering=0) as output:
                        for offset in offsets:  # Claimed synchronously, before any await.
                            result = await connection.invoke(functions.upload.getFile(location=location, offset=offset, limit=PART_SIZE))
                            if result.name != "upload.file":
                                raise UnsupportedFeature("CDN redirects are not implemented")
                            if len(result.bytes) != min(PART_SIZE, size - offset):
                                raise OSError("Unexpected downloaded file size")
                            await _disk(_write_at, output, offset, result.bytes)

                parts = (size + PART_SIZE - 1) // PART_SIZE
                await _parallel(*(receive() for _ in range(min(concurrency, parts))))
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination
