"""Authorized TCP callback listeners bridged to browser WebSockets."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from app import config
from app.queue_utils import offer_latest


def is_wsl_environment() -> bool:
    if os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().casefold()
    except OSError:
        return False


def discover_callback_route(target: str) -> tuple[str, str]:
    try:
        addresses = socket.getaddrinfo(target, 9, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}'") from exc

    for family, socket_type, protocol, _, sockaddr in addresses:
        route_socket = socket.socket(family, socket_type, protocol)
        try:
            route_socket.connect(sockaddr)
            callback_host = str(route_socket.getsockname()[0])
            target_host = str(sockaddr[0])
            prefix_length = 32 if family == socket.AF_INET else 128
            return callback_host, f"{target_host}/{prefix_length}"
        except OSError:
            continue
        finally:
            route_socket.close()
    raise ValueError(f"No local route to target '{target}'")


@dataclass
class Session:
    id: str
    listener_id: str
    peer: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    connected_at: float = field(default_factory=time.time)
    closed: bool = False
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    transcript: bytearray = field(default_factory=bytearray, repr=False)


@dataclass
class RejectedConnection:
    peer: str
    rejected_at: float = field(default_factory=time.time)
    reason: str = "source_not_allowed"


@dataclass
class Listener:
    id: str
    port: int
    label: str
    allowed_network: ipaddress.IPv4Network | ipaddress.IPv6Network
    server: asyncio.base_events.Server
    created_at: float = field(default_factory=time.time)
    sessions: dict[str, Session] = field(default_factory=dict)
    rejected_connections: list[RejectedConnection] = field(default_factory=list)


class BackConnectManager:
    def __init__(self) -> None:
        self.listeners: dict[str, Listener] = {}

    async def start_listener(self, port: int, allowed_source: str, label: str | None) -> Listener:
        listener_id = str(uuid.uuid4())
        allowed_network = ipaddress.ip_network(allowed_source, strict=False)

        async def _on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await self._handle_client(listener_id, reader, writer)

        server = await asyncio.start_server(
            _on_client,
            host=config.LISTENER_BIND_HOST,
            port=port,
            start_serving=False,
        )
        listener = Listener(
            id=listener_id,
            port=port,
            label=label or f"listener-{port}",
            allowed_network=allowed_network,
            server=server,
        )
        self.listeners[listener_id] = listener
        try:
            await server.start_serving()
        except Exception:
            self.listeners.pop(listener_id, None)
            server.close()
            await server.wait_closed()
            raise
        return listener

    async def _handle_client(self, listener_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        listener = self.listeners.get(listener_id)
        if not listener:
            writer.close()
            return

        peer = writer.get_extra_info("peername")
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        if not peer or ipaddress.ip_address(peer[0].split("%", 1)[0]) not in listener.allowed_network:
            listener.rejected_connections.append(RejectedConnection(peer=peer_str))
            listener.rejected_connections = listener.rejected_connections[-20:]
            writer.close()
            await writer.wait_closed()
            return
        session = Session(id=str(uuid.uuid4()), listener_id=listener_id, peer=peer_str, reader=reader, writer=writer)
        listener.sessions[session.id] = session

        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                session.transcript.extend(chunk)
                if len(session.transcript) > 262_144:
                    del session.transcript[:-262_144]
                for q in list(session.subscribers):
                    item = chunk
                    if q.full():
                        item = b"\r\n[web-gui] WARNING: Live session output was truncated because this subscriber fell behind.\r\n" + chunk
                    offer_latest(q, item)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            session.closed = True
            for q in list(session.subscribers):
                offer_latest(q, None)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    def list_listeners(self) -> list[Listener]:
        return list(self.listeners.values())

    def get_listener(self, listener_id: str) -> Listener | None:
        return self.listeners.get(listener_id)

    def get_session(self, session_id: str) -> Session | None:
        for listener in self.listeners.values():
            if session_id in listener.sessions:
                return listener.sessions[session_id]
        return None

    async def send_input(self, session_id: str, data: bytes) -> bool:
        session = self.get_session(session_id)
        if not session or session.closed:
            return False
        session.writer.write(data)
        await session.writer.drain()
        return True

    def subscribe(self, session_id: str) -> tuple[asyncio.Queue, bytes, bool] | None:
        session = self.get_session(session_id)
        if not session:
            return None
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        transcript = bytes(session.transcript)
        session.subscribers.append(q)
        return q, transcript, session.closed

    def unsubscribe(self, session_id: str, q: asyncio.Queue) -> None:
        session = self.get_session(session_id)
        if session and q in session.subscribers:
            session.subscribers.remove(q)

    async def close_session(self, session_id: str) -> None:
        session = self.get_session(session_id)
        if session:
            session.writer.close()
            session.closed = True
            try:
                await session.writer.wait_closed()
            except ConnectionError:
                pass

    async def stop_listener(self, listener_id: str) -> None:
        listener = self.listeners.pop(listener_id, None)
        if not listener:
            return
        for session in listener.sessions.values():
            if not session.closed:
                session.writer.close()
        listener.server.close()
        await listener.server.wait_closed()


backconnect_manager = BackConnectManager()
