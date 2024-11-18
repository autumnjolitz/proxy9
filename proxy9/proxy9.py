#!/usr/bin/env python3.12 -X dev
"""
Name: proxy9
Description: UDP/TCP asyncio proxy/forwarder
Author: Autumn Jolitz
License: BSD
Classifiers:
    License :: OSI Approved :: BSD License
    Topic :: Internet :: Proxy Servers
    Development Status :: 5 - Production/Stable
    Environment :: Console
    Operating System :: Unix
    Operating System :: POSIX :: Linux
    Intended Audience :: Developers
    Intended Audience :: Information Technology
    Intended Audience :: System Administrators
    Programming Language :: Python :: 3.12
"""

import asyncio
import datetime
import functools
import logging
import os
import os.path
import platform
import re
import io
import socket
import shlex
import stat
import ssl
import struct
import sys
import tempfile
import traceback
import weakref
from collections.abc import Mapping, Iterable, Awaitable, Buffer
from contextlib import suppress, asynccontextmanager, AsyncExitStack
from enum import IntFlag, Enum
from ipaddress import ip_address, IPv4Address, IPv6Address
from pathlib import Path
from typing import (
    Any,
    assert_never,
    AsyncContextManager,
    Literal,
    NamedTuple,
    NewType,
    Protocol,
    Self,
    TypeGuard,
)
from urllib.parse import urlsplit, SplitResult, parse_qsl, urlencode

try:
    from uvloop import install as install_uvloop
except ImportError:
    pass
else:
    if os.environ.get("PROXY9_NO_UVLOOP", "").lower() in (
        "yes",
        "1",
        "on",
        "aye",
        "t",
        "true",
    ):
        pass
    else:
        install_uvloop()
        print("uvloop installed", file=sys.stderr)

root_logger = logger = logging.getLogger(
    __name__ if __name__ != "__main__" else f"{os.path.splitext(__file__)[0]}"
)
access_log = logging.getLogger(
    f"{__name__}.access_log"
    if __name__ != "__main__"
    else f"{os.path.splitext(__file__)[0]}.access_log"
)

Elapsed = NewType("Elapsed", float)


match os_platform := platform.platform():
    case "Linux":
        UNNAMED_UNIX_SOCKET_ADDR = "/proc/{1}/fd/{0}"

        def get_peer_pid(client_sock: socket.socket) -> int:
            pid, uid, gid = memoryview(
                client_sock.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                )
            ).cast("i")
            return pid

    case "Darwin":
        UNNAMED_UNIX_SOCKET_ADDR = "/dev/fd/{0}:{1}"

        def get_peer_pid(client_sock: socket.socket) -> int:
            return client_sock.getsockopt(0, 0x002)

    case "DragonFly":
        UNNAMED_UNIX_SOCKET_ADDR = "/dev/fd/{0}"

        def get_peer_pid(client_sock: socket.socket):
            return -1

    case _:

        def get_peer_pid(client_sock: socket.socket):
            return -1

        UNNAMED_UNIX_SOCKET_ADDR = "/dev/fd/{0}"


class BaseCertificate:
    __slots__ = ()

    @property
    def certificate(self) -> str:
        return self.raw_certificate.decode()

    @property
    def private_key(self) -> str:
        return self.raw_private_key.decode()

    def load_context(self, ctx):
        ctx.load_verify_locations(cadata=self.certificate)
        return ctx


class _RootCertificate(NamedTuple):
    raw_certificate: bytes
    raw_private_key: bytes


class RootCertificate(BaseCertificate, _RootCertificate):
    __slots__ = ()


class _TLSCertificate(NamedTuple):
    raw_certificate: bytes
    raw_private_key: bytes


class TLSCertificate(BaseCertificate, _TLSCertificate):
    __slots__ = ()


class Request:
    def __init_subclass__(cls):
        if not hasattr(cls, "socket"):
            raise ValueError(f"must have socket attr on {cls}")
        return super.__init_subclass__()

    @functools.cached_property
    def remote_addr(self):
        match (self.socket.family, self.socket.type):
            case (family, type) if family in (
                socket.AF_INET,
                socket.AF_INET6,
            ) and type is socket.SOCK_STREAM:
                addr, port = self.socket.getpeername()
                return RemoteIp(ip_address(addr), port)
            case (family, type) if family in (
                socket.AF_INET,
                socket.AF_INET6,
            ) and type is socket.SOCK_DGRAM:
                return RemoteIp(ip_address(self.remote_ip), self.remote_port)
            case (socket.AF_UNIX, _):
                named_socket = self.socket.getpeername()
                peer_pid = get_peer_pid(self.socket)
                if named_socket == "":
                    named_socket = UNNAMED_UNIX_SOCKET_ADDR.format(self.socket.fileno(), peer_pid)
                return Path(named_socket)
            case _:
                raise NotImplementedError

    @functools.cached_property
    def response(self):
        return Response(self)

    @property
    def is_closing(self) -> bool:
        return self.is_closed.is_set()

    @is_closing.setter
    def is_closing(self, val: bool) -> bool:
        if val:
            self.is_closed.set()
        else:
            self.is_closed.clear()
        return self.is_closed.is_set()

    def close(self):
        if self.is_closing:
            logger.warning(f"Already closed on {self!r}")
            return
        self.is_closing = True
        with suppress(RuntimeError, ValueError):
            loop = asyncio.get_running_loop()
            loop.remove_reader(self.socket.fileno())
            loop.remove_writer(self.socket.fileno())
        self.socket.close()

    def read(self, size=-1, *, future=None):
        if size == -1:
            size = 4096
        loop = asyncio.get_running_loop()
        f = loop.create_future()
        with suppress(BlockingIOError, InterruptedError):
            b = self.socket.recv(size)
            if future is not None and not future.done():
                future.set_result(b)
                return
            f.set_result(b)
            return f
        loop.add_reader(self.socket.fileno(), functools.partial(self.read, size, future=f))
        return f


def truncate(s: bytes | str, /, length: int):
    if len(s) > length:
        with suppress(UnicodeError):
            if hasattr(s, "decode"):
                s = s.decode()
                return f"{s[:length]}…"
        s = s[:length]
        if isinstance(s, str):
            return f"{s}…"
        return bytes(s) + "…".encode()


class Response:
    def __init__(self, request, buffer=None):
        self._request = request
        self._buffer = bytearray(4096)
        self._length = 0

    def write(self, b: bytes) -> int:
        size = len(b)
        index = self._length
        with memoryview(self._buffer) as buffer, buffer[index : index + size] as view:
            if len(view) < size:
                size = len(view)
            view[0:size] = b[:size]
            self._length += size
        if not size:
            raise ValueError("no space left", self._length)
        logger.debug(f"wrote {size:,} bytes ({truncate(b, 100)})")
        return size

    def drain(self, *, future=None, view=None) -> Awaitable[int]:
        loop = asyncio.get_running_loop()
        if future is not None:
            loop.remove_writer(self._request.socket.fileno())
        size = self._length
        if view is None:
            view = memoryview(self._buffer)[0:size]
        try:
            n = self._request.socket.send(view)
        except (BlockingIOError, InterruptedError):
            f = loop.create_future()
            loop.add_writer(
                self._request.socket.fileno(),
                functools.partial(self.drain, view=view, future=f),
            )
            return f
        else:
            remainder = view[n:]
            self._length -= n
            if remainder:
                perror("remainder", remainder, len(remainder), "bytes")
                f = loop.create_future()
                loop.add_writer(self._request.socket.fileno(), self._drain, remainder, f, n)
                return f
        f = loop.create_future()
        f.set_result(n)
        if future:
            future.set_result(n)
        return f

    def _drain(self, view: memoryview, future: asyncio.Future, count):
        try:
            n = self._request.socket.send(view)
        except BrokenPipeError:
            perror("lost", view.tobytes())
        else:
            assert len(view) == n, "wtf"
            self._length = 0
            future.set_result(n + count)
            perror("fixt")


type IPAddress = IPv4Address | IPv6Address


class _RemoteIp(NamedTuple):
    ip: IPAddress
    port: int


class RemoteIp(_RemoteIp):
    __slots__ = ()

    def __str__(self) -> str:
        if isinstance(self.ip, IPv6Address):
            return f"[{self.ip!s}]:{self.port}"
        return f"{self.ip}:{self.port}"


class ConfigurationMixin:
    __slots__ = ()

    def __getitem__(self, m: int | slice | str):
        if isinstance((attr := m), str):
            return self.configuration[attr]
        return super().__getitem__(m)


class TcpFamily:
    __slots__ = ()

    @property
    def family(self):
        if isinstance(self.hostname, IPv4Address):
            return socket.AF_INET
        elif isinstance(self.hostname, IPv6Address):
            return socket.AF_INET6
        return None

    @property
    def type(self):
        return socket.SOCK_STREAM


class _HttpSocket(NamedTuple):
    hostname: str
    port: int
    parsed_url: SplitResult
    query_parameters: Mapping[str, tuple[str, ...]]


class HttpSocket(TcpFamily, _HttpSocket):
    __slots__ = ()

    def __getitem__(self, key_or_int_or_slice: int | str | slice):
        if isinstance(key_or_int_or_slice, str):
            key: str = key_or_int_or_slice
            return self.query_parameters[key]
        int_or_slice: int | slice = key_or_int_or_slice
        return super().__getitem__(int_or_slice)

    @classmethod
    def new(cls, hostname: str, port: int, parsed_url: SplitResult | None = None):
        mapping = {}
        if parsed_url is None:
            match port:
                case 443:
                    proto = "https"
                case 80:
                    proto = "http"
                case _:
                    proto = "http"
            parsed_url = urlsplit(f"{proto}://{hostname}:{port}/")
        if parsed_url.query:
            for key, value in parse_qsl(parsed_url.query, keep_blank_values=True):
                try:
                    mapping[key].append(value)
                except KeyError:
                    mapping[key] = [value]
        return cls(
            hostname,
            port,
            parsed_url,
            {key: tuple(values) for key, values in mapping.items()},
        )
        if parsed_url.query:
            for key, value in parse_qsl(parsed_url.query, keep_blank_values=True):
                try:
                    mapping[key].append(value)
                except KeyError:
                    mapping[key] = [value]
        return cls(
            hostname,
            port,
            parsed_url,
            {key: tuple(values) for key, values in mapping.items()},
        )


class _UdpSocket(NamedTuple):
    hostname: str | IPv6Address | IPv4Address
    port: int
    parsed_url: SplitResult
    query_parameters: Mapping[str, tuple[str, ...]]


class UdpSocket(_UdpSocket):
    __slots__ = ()

    def __str__(self):
        return f"{self.hostname or ''}:{self.port}"

    @property
    def family(self):
        return socket.AF_INET

    @property
    def type(self):
        return socket.SOCK_DGRAM

    @classmethod
    def new(cls, hostname: str, port: int, parsed_url: SplitResult | None = None):
        mapping = {}
        if parsed_url is None:
            parsed_url = urlsplit(f"udp://{hostname}:{port}")
        if parsed_url.query:
            for key, value in parse_qsl(parsed_url.query, keep_blank_values=True):
                try:
                    mapping[key].append(value)
                except KeyError:
                    mapping[key] = [value]
        if isinstance(hostname, str) and (address := maybe_ipaddress(hostname)) is not None:
            hostname = address
        return cls(
            hostname,
            port,
            parsed_url,
            {key: tuple(values) for key, values in mapping.items()},
        )


class _TcpSocket(NamedTuple):
    hostname: str
    port: int
    parsed_url: SplitResult | None
    query_parameters: Mapping[str, tuple[str, ...]]


class TcpSocket(TcpFamily, _TcpSocket):
    __slots__ = ()

    def __str__(self):
        if self.query_parameters:
            return (
                f"{self.hostname or ''}:{self.port}?{urlencode(self.query_parameters, doseq=True)}"
            )
        return f"{self.hostname or ''}:{self.port}"

    @classmethod
    def new(cls, hostname: str, port: int, parsed_url=None):
        mapping = {}
        if parsed_url is None:
            parsed_url = urlsplit(f"tcp://{hostname}:{port}")
        if parsed_url.query:
            for key, value in parse_qsl(parsed_url.query, keep_blank_values=True):
                try:
                    mapping[key].append(value)
                except KeyError:
                    mapping[key] = [value]
        return cls(
            hostname,
            port,
            parsed_url,
            {key: tuple(values) for key, values in mapping.items()},
        )


class _UnixSocket(NamedTuple):
    file: Path
    configuration: Mapping[str, str]

    @property
    def query_parameters(self):
        return self.configuration


class UnixSocket(ConfigurationMixin, _UnixSocket):
    __slots__ = ()

    def __str__(self):
        if self.configuration:
            return f"{self.file!s}?{urlencode(self.configuration, doseq=True)}"
        return f"{self.file!s}"

    async def cleanup(self, s: socket.socket):
        loop = asyncio.get_running_loop()
        filename = await loop.run_in_executor(None, s.getsockname)
        with suppress(FileNotFoundError):
            os.remove(filename)

    @property
    def type(self):
        return self["type"]

    @classmethod
    def new(
        cls,
        filename: str,
        configuration: (
            str | Mapping[str, tuple[str, ...] | str] | Iterable[tuple[str, tuple[str, ...] | str]]
        ) = "",
        *,
        default_type=socket.SOCK_STREAM,
    ):
        conf = {}
        if configuration:
            if isinstance(configuration, str):
                iterable = parse_qsl(configuration, keep_blank_values=True)
            elif isinstance(configuration, Mapping):
                iterable = tuple(
                    (
                        key,
                        (
                            (values := configuration[key])
                            if isinstance(configuration[key], (tuple, list))
                            else (value := configuration[key])
                        ),
                    )
                    for key in configuration
                )
            elif isinstance(configuration, Iterable) and not isinstance(
                configuration, (bytearray, bytes, memoryview)
            ):
                iterable = tuple(
                    (
                        key,
                        (values := value) if isinstance(value, (tuple, list)) else (value,),
                    )
                    for key, value in configuration
                )
            else:
                raise TypeError(type(configuration))
            for key, value in iterable:
                if key == "type":
                    if isinstance(value, (tuple, list)):
                        *rest, value = value
                    assert value in ("SOCK_STREAM", "SOCK_DGRAM")
                    conf["type"] = getattr(socket, value)
                else:
                    conf.setdefault(key, [])
                    conf[key].append(value)
        conf.setdefault("type", default_type)
        return cls(
            Path(filename),
            {
                key: tuple(values) if isinstance((values := value), (tuple, list)) else value
                for key, value in conf.items()
            },
        )


DOMAIN_REGEX = re.compile(
    r"^(((?!-))(xn--|_)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?(?P<tld>[a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$",
    re.DOTALL,
)


def maybe_ipaddress(
    o: int | str | IPv6Address | IPv4Address,
) -> IPv4Address | IPv6Address | None:
    if isinstance(o, (IPv6Address, IPv4Address)):
        return o
    with suppress(ValueError):
        return ip_address(o)
    return None


ALL_INTERFACES = ""


def perror(*args):
    return print(*args, file=sys.stderr, flush=True)


class ProxyOptions(IntFlag):
    REUSE_PORT = 1
    USE_DUALSTACK_IF_AVAILABLE = 2


def bind_unix_socket(my_address: UnixSocket, backlog: int = 10):
    assert isinstance(my_address.file, Path)
    assert my_address.type in (socket.SOCK_DGRAM, socket.SOCK_STREAM)

    s = socket.socket(socket.AF_UNIX, my_address.type)
    os.set_blocking(s.fileno(), False)

    assert os.get_blocking(s.fileno()) is False

    with suppress(FileNotFoundError):
        os.remove(my_address.file)
    s.bind(f"{my_address.file}")
    match s.type:
        case socket.SOCK_STREAM:
            s.listen(backlog)
        case socket.SOCK_DGRAM:
            pass
        case _:
            raise ValueError(f"{s.type}?!")
    return s


def bind_udp_socket(
    my_address: UdpSocket,
    /,
    backlog: int = 10,
    family=socket.AF_INET,
    *,
    reuse_port: bool = False,
    dualstack_ipv6: bool = False,
):
    if dualstack_ipv6:
        family = socket.AF_INET6
    s = socket.socket(my_address.family or family, my_address.type)
    os.set_blocking(s.fileno(), False)
    assert os.get_blocking(s.fileno()) is False
    if reuse_port:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((my_address.hostname or "", my_address.port))
    # s.listen(backlog)
    return s


def bind_tcp_socket(
    addr: tuple[str, int],
    family,
    backlog: int = 10,
    *,
    reuse_port=False,
    dualstack_ipv6=False,
):
    s = socket.create_server(
        addr,
        family=family,
        dualstack_ipv6=dualstack_ipv6,
        reuse_port=reuse_port,
        backlog=backlog,
    )
    if reuse_port:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    os.set_blocking(s.fileno(), False)
    assert os.get_blocking(s.fileno()) is False
    return s


@asynccontextmanager
async def proxy_between(
    my_address: TcpSocket | UdpSocket | UnixSocket | HttpSocket,
    their_address,
    *,
    options: ProxyOptions | None = None,
    backlog=10,
):
    loop = asyncio.get_running_loop()
    if options is None:
        options = ProxyOptions.USE_DUALSTACK_IF_AVAILABLE
    dualstack_ipv6 = (
        socket.has_dualstack_ipv6()
        and ProxyOptions.USE_DUALSTACK_IF_AVAILABLE & options
        == ProxyOptions.USE_DUALSTACK_IF_AVAILABLE
    )

    match my_address:
        case (hostname, port, *_) if isinstance(my_address, TcpFamily):
            addr = (hostname, port)
            if dualstack_ipv6:
                family = socket.AF_INET6
            elif (family := my_address.family) is not None:
                ...
            else:
                family = socket.AF_INET

            sock = await loop.run_in_executor(
                None,
                functools.partial(
                    bind_tcp_socket,
                    reuse_port=options & ProxyOptions.REUSE_PORT == ProxyOptions.REUSE_PORT,
                    dualstack_ipv6=dualstack_ipv6,
                ),
                addr,
                family,
                backlog,
            )
        case UnixSocket():
            sock = await loop.run_in_executor(None, bind_unix_socket, my_address)
        case UdpSocket():
            hostname, port, parsed_url, *_ = my_address
            match parsed_url:
                case (_, netloc, path) if netloc == "" and path:
                    sock = await loop.run_in_executor(None, bind_unix_socket, Path(path))
                case _:
                    sock = await loop.run_in_executor(
                        None,
                        functools.partial(
                            bind_udp_socket,
                            reuse_port=options & ProxyOptions.REUSE_PORT
                            == ProxyOptions.REUSE_PORT,
                            dualstack_ipv6=dualstack_ipv6,
                        ),
                        my_address,
                    )
        case _:
            assert_never(my_address)
    async with Proxy(my_address, sock, their_address) as server:
        yield server
        await server.run_forever()


class SharedFileDescriptor(NamedTuple):
    fd: int
    created_at: int

    def fileno(self) -> int:
        return self.fd

    @classmethod
    def new(cls, fd: int, now=None):
        loop = asyncio.get_running_loop()
        if now is None:
            now = loop.time()
        return cls(fd, now)


DEFAULT_RECVMSG_FLAGS = socket.MSG_OOB

type AddressType = UdpSocket | UnixSocket | TcpSocket | HttpSocket


class _UnixRequest(NamedTuple):
    address: Path
    socket: socket.socket
    server_address: AddressType
    type_of: Literal[socket.SOCK_STREAM, socket.SOCK_DGRAM]
    is_closed: asyncio.Event


class _UdpRequest(NamedTuple):
    remote_ip: IPAddress | str
    remote_port: int
    socket: socket.socket
    server_address: AddressType
    is_closed: asyncio.Event
    type: Literal[socket.SOCK_DGRAM]


class UdpRequest(Request, _UdpRequest):
    __slots__ = ()

    @property
    def scheme(self):
        return "udp"

    @classmethod
    def new(
        cls,
        host: IPAddress,
        port: int,
        sock: socket.socket,
        server_address: AddressType,
        type: Literal[socket.SOCK_DGRAM],
        is_closed=None,
    ):
        assert sock.type is socket.SOCK_DGRAM
        if is_closed is None:
            is_closed = asyncio.Event()
        return cls(host, port, sock, server_address, is_closed, type)


# UdpRequest.new(host, port, client_sock, self.address, client_sock.type)
class UnixRequest(Request, _UnixRequest):
    __slots__ = ()

    @property
    def scheme(self):
        if self.socket.type is socket.SOCK_DGRAM:
            return "unix+udp"
        return "unix"

    @classmethod
    def new(
        cls,
        socket: socket.socket,
        address: Path,
        server_address: AddressType,
        type: Literal[socket.SOCK_STREAM, socket.SOCK_DGRAM],
        is_closed=None,
    ):
        if is_closed is None:
            is_closed = asyncio.Event()
        return cls(address, socket, server_address, type, is_closed)


class _HttpRequest(NamedTuple):
    remote_ip: IPAddress | str
    remote_port: int
    socket: socket.socket
    server_address: AddressType
    is_closed: asyncio.Event


class HttpRequest(Request, _HttpRequest):
    __slots__ = ()

    @classmethod
    def new(
        cls,
        socket: socket.socket,
        address: str,
        port: int,
        server_address,
        is_closed=None,
    ):
        if is_closed is None:
            is_closed = asyncio.Event()
        if (parsed_address := maybe_ipaddress(address)) is not None:
            return cls(parsed_address, port, socket, server_address, is_closed)
        return cls(address, port, socket, server_address, is_closed)

    @property
    def scheme(self):
        return "http"


class _TcpRequest(NamedTuple):
    remote_ip: IPAddress | str
    remote_port: int
    socket: socket.socket
    server_address: AddressType
    is_closed: asyncio.Event


class TcpRequest(Request, _TcpRequest):
    __slots__ = ()

    @property
    def scheme(self):
        return "tcp"

    @classmethod
    def new(
        cls,
        socket: socket.socket,
        address: str,
        port: int,
        server_address,
        is_closed=None,
    ):
        if is_closed is None:
            is_closed = asyncio.Event()
        if (parsed_address := maybe_ipaddress(address)) is not None:
            return cls(parsed_address, port, socket, server_address, is_closed)
        return cls(address, port, socket, server_address, is_closed)


class _Message(NamedTuple):
    index: int
    length: int
    span: memoryview
    flags: int
    from_address: str | None
    events: tuple[SharedFileDescriptor, ...]


class Message(_Message):
    __slots__ = ()

    def __str__(self):
        return f"{type(self).__name__}(index={self.index}, length={self.length}, span={self.span.tobytes().decode('utf8', 'backslashreplace')!r}, from_address={self.from_address!r}, events={self.events!r})"

    def __enter__(self):
        self.span.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self.span.__exit__(exc_type, exc_value, traceback)

    @classmethod
    def new(cls: type[Self], index, span, flags, from_address, events):
        return cls(index, len(span), span, flags, from_address, events)


class Session(NamedTuple):
    request: HttpRequest | TcpRequest | UnixRequest
    task: asyncio.Task


def is_errored(f, name: str):
    with suppress(asyncio.CancelledError):
        if e := f.exception():
            logger.exception(f"[{name}] Future {f} had uncaught exception", exc_info=e)


def report_uncaught_error(func):
    @functools.wraps(func)
    async def wrapped(*args, **kwargs):
        this = asyncio.current_task()
        name = this.get_name()
        if not name:
            name = f"<anonymous asyncio task-{this!r}>"
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            if isinstance(e, (asyncio.CancelledError, asyncio.TimeoutError)):
                raise
            logger.exception(
                f"uncaught exception in {name} ({func.__name__})",
                extra={"data": {"this": name}},
            )
            raise

    return wrapped


async def _iter_read(source: asyncio.StreamReader | Request, size: int, /):
    while (b_or_future := source.read(size)) != b"":
        if isinstance(b_or_future, Awaitable):
            b = await b_or_future
        elif isinstance(b_or_future, (bytearray, bytes, memoryview)):
            b = b_or_future
        else:
            raise TypeError(type(b_or_future))
        if b == b"":
            break
        yield b


class HasDrain(Protocol):
    def drain(self) -> Awaitable[None] | None: ...


class DrainStatus(Enum):
    DRAINED = "drained"
    UNSUPPORTED = "drain not supported"


def maybe_drainable(d: Any) -> TypeGuard[HasDrain]:
    if (thunk := getattr(d, "drain", None)) is not None:
        return callable(thunk)
    return False


async def drain_if_exist(destination, /) -> DrainStatus:
    if not maybe_drainable(destination):
        return DrainStatus.UNSUPPORTED
    result_or_awaitable = destination.drain()
    if isinstance(result_or_awaitable, Awaitable):
        result = await result_or_awaitable
    elif result_or_awaitable is None:
        result = None
    else:
        result = result_or_awaitable
        logger.error(f"{destination.drain} returned a non-null - {result!r}")
    return DrainStatus.DRAINED


async def _write(destination: asyncio.StreamWriter | Response, b: bytes, /) -> int:
    n = 0
    # assert isinstance(destination, (asyncio.StreamWriter, Response)), f"Not supported - {type(destination)}"
    supports_drain = await drain_if_exist(destination)
    with memoryview(b) as buffer:
        view = buffer[:]
        if isinstance(n := destination.write(view), Awaitable):
            n = await n
        elif isinstance(n, int):
            pass
        elif n is None:
            n = len(b)
        else:
            assert_never(n)
        if supports_drain is not DrainStatus.UNSUPPORTED:
            supports_drain = await drain_if_exist(destination)
        while n < len(b):
            view = buffer[n:]
            logger.debug(f"need to write remainder {len(view)} bytes to {destination}")
            if isinstance(n_or_future := destination.write(view), Awaitable):
                n += await n_or_future
            elif isinstance(n_or_future, int):
                n += n_or_future
            else:
                assert_never(n_or_future)
            if supports_drain is not DrainStatus.UNSUPPORTED:
                supports_drain = await drain_if_exist(destination)
    return n


@report_uncaught_error
async def copy_between(
    source: asyncio.StreamReader | Request,
    destination: asyncio.StreamWriter | Request,
    *,
    prefix_bytes: bytes = b"",
):
    loop = asyncio.get_running_loop()
    read_count = 0
    sent_count = 0
    t_main = loop.time()
    if prefix_bytes:
        n = await _write(destination, prefix_bytes)
        sent_count += n

    async for blob in _iter_read(source, 4096):
        read_count += len(blob)
        t_s = loop.time()
        n = await _write(destination, blob)
        sent_count += n
        t_e = loop.time() - t_s
        if t_e > 1:
            logger.warning(f"Slow writing {n} bytes to {destination}")
        logger.debug(f"Wrote {n or len(blob)} bytes to {destination}")
    if isinstance(destination, asyncio.StreamWriter):
        if not destination.is_closing:
            try:
                await drain_if_exist(destination)
            except (OSError, BrokenPipeError, ConnectionResetError) as e:
                logger.error(f"unable to drain - {destination} {e!r}")

    return CopyStats.new(loop.time() - t_main, read_count, sent_count)


class _CopyStats(NamedTuple):
    elapsed: Elapsed
    read_bytes_count: int
    sent_bytes_count: int


class CopyStats(_CopyStats):
    __slots__ = ()

    @classmethod
    def new(cls, elapsed: float, read_bytes_count: int, sent_bytes_count: int):
        return cls(Elapsed(elapsed), read_bytes_count, sent_bytes_count)

    def __add__(self: Self, other: Self | Any):
        if isinstance(other, type(self)):
            return SumStats.new(self, other)
        return super().__add__(other)


class SumStats:
    times: tuple[Elapsed, ...]
    total_read_bytes_count: int
    total_sent_bytes_count: int
    samples: tuple[CopyStats, ...]

    def __repr__(self):
        s = super().__repr__()
        index = s.rindex(")")
        return f"{s[:index]}, upload_rate={self.upload_rate}, download_rate={self.download_rate}, elapsed={self.elapsed}{s[index:]}"

    @property
    def upload_rate(self) -> float:
        return self.total_sent_bytes_count / sum(self.times)

    @property
    def elapsed(self) -> Elapsed:
        return Elapsed(sum(self.times))

    @property
    def download_rate(self) -> float:
        return self.total_read_bytes_count / sum(self.times)

    @classmethod
    def new(cls: type[Self], *stats: CopyStats) -> Self:
        times = []
        total_read = 0
        total_sent = 0
        for s in stats:
            times.append(s.elapsed)
            total_read += s.read_bytes_count
            total_sent += s.sent_bytes_count
        samples = tuple(stats)
        return cls(tuple(times), total_read, total_sent, samples)

    def __add__(self: Self, other: Self):
        cls = type(self)
        if isinstance(other, cls):
            return cls.new(*self.samples, *other.samples)
        elif isinstance(other, CopyStats):
            return cls.new(*(*self.samples, other))
        return super().__add__(other)


async def copy(
    name: str,
    source: asyncio.StreamReader | Request,
    dest: asyncio.StreamWriter | Response,
    *,
    prefix_bytes: bytes = b"",
) -> tuple[Elapsed, tuple[int, ...]]:
    this = asyncio.current_task()
    loop = asyncio.get_running_loop()
    this.add_done_callback(functools.partial(is_errored, name=name))
    t = loop.create_task(copy_between(source, dest, prefix_bytes=prefix_bytes))
    t.set_name(f"Copy[{name}]-{source}-{dest}")
    elapsed, *stats = await t
    return Elapsed(elapsed), stats


class _Connection(NamedTuple):
    address: AddressType
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    tls: ssl.SSLContext | None | tuple[ssl.SSLContext, str]


class Connection(_Connection):
    __slots__ = ()

    @property
    def type(self):
        return self.writer.get_extra_info("socket").type

    @property
    def family(self):
        return self.writer.get_extra_info("socket").family

    async def start_tls(self, *args, **kwargs):
        return await self.writer.start_tls(*args, **kwargs)


MAX_UNIX_DATAGRAM_SIZE = 65_507
MAX_INET_DATAGRAM_SIZE = 508


class AsyncDatagramReader:
    def __init__(
        self,
        destination: UdpSocket | UnixSocket,
        sock: socket.socket,
        buffer: bytearray | memoryview | None = None,
        *,
        max_message_size=None,
    ):
        if buffer is None:
            buffer = bytearray(MAX_UNIX_DATAGRAM_SIZE)
        self.socket = sock
        self.buffer = buffer
        self.index = 0
        match self.socket.family:
            case socket.AF_UNIX:
                default_max_size = MAX_UNIX_DATAGRAM_SIZE
            case socket.AF_INET | socket.AF_INET6:
                default_max_size = MAX_INET_DATAGRAM_SIZE
            case _:
                raise NotImplementedError
        if max_message_size is None:
            max_message_size = default_max_size
        self.max_message_size = max_message_size

        match destination:
            case UdpSocket():
                self.destination = (f"{destination.hostname!s}", destination.port)
            case UnixSocket():
                self.destination = str(destination.file)
            case _:
                raise TypeError(destination)

    async def recvmsg(self, size=-1, *, buffer=None) -> Message:
        if size == -1:
            size = MAX_UNIX_DATAGRAM_SIZE
        index = 0
        if buffer is None:
            index = self.index
            buffer = memoryview(self.buffer)
        with memoryview(buffer)[:MAX_UNIX_DATAGRAM_SIZE] as buf, buf[index:size] as view:
            logger.debug(f"reading {self.socket} into {view}")
            msg: Message = await recvmsg_into(self.socket, view)
            logger.debug(f"reading {self.socket} into {view} -> {msg!r}")
        return msg


class AsyncDatagramWriter:
    def __init__(self, address: UdpSocket | UnixSocket, socket: socket.socket):
        self.address = address
        self.socket = socket
        self.buffer = bytearray(MAX_UNIX_DATAGRAM_SIZE)
        self.index = 0
        self.is_closed = False
        self._sent_buf = None
        self._task = None

    def __repr__(self):
        values = ""
        for key, value in vars(self).items():
            if key == "buffer":
                continue
            if values:
                values = f"{values}, {key}={value!r}"
            else:
                values = f"{key}={value!r}"
        return f"{type(self).__name__}({values})"

    def write(self, b: bytes, /):
        self.buffer[self.index : self.index + len(b)] = b
        self.index += len(b)
        return len(b)

    async def drain(self):
        # perror('draining')
        if self._sent_buf is not None:
            return
        if self.index:
            await self._send_message()

    def close(self):
        if self.is_closed:
            return
        # loop = asyncio.get_running_loop()
        if not self._sent_buf:
            self._send_message()
        self.socket.close()
        self.is_closed = True

    async def wait_closed(self):
        if self._task:
            with suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await self._task
            self._task = None

    def _send_message(self, *, future: asyncio.Future | None = None):
        loop = asyncio.get_running_loop()
        if future is not None:
            loop.remove_writer(self.socket.fileno())
            logger.debug(f"got callback on {self.socket}")
        if future is None:
            future = loop.create_future()
        if self._sent_buf is not None:
            if not future.done():
                future.set_result(self._sent_buf)
            return future
        if self.index == 0:
            raise ValueError("nothing written first?!")
        with suppress(BlockingIOError, InterruptedError):
            with memoryview(self.buffer) as buf, buf[: self.index] as view:
                # try:
                #     n = self.socket.send(view)
                # except OSError as e:
                #     if e.errno == 39:
                #         perror(f"{self!r} wtf")
                #         match self.address:
                #             case UnixSocket():
                #                 n = self.socket.sendto(view, f"{self.address.file!s}")
                #             case UdpSocket():
                #                 n = self.socket.sendto(view, (f"{self.address.hostname}", self.address.port))
                #             case _:
                #                 assert False, f"{self.address!r} wtf"
                #     else:
                #         raise
                # else:
                #     logger.warning(f"{self!r} not-wtf")
                match response_from := first_or_null(
                    self.address.query_parameters.get("response-from")
                ):
                    case "server-socket":
                        match self.address:
                            case UnixSocket():
                                n = self.socket.sendto(view, f"{self.address.file!s}")
                            case UdpSocket():
                                n = self.socket.sendto(
                                    view,
                                    (f"{self.address.hostname}", self.address.port),
                                )
                            case _:
                                assert_never(self.address)
                    case None | "new-socket":
                        # perror(response_from, "WTJA")
                        n = self.socket.send(view)
                    case _:
                        assert_never(response_from)

                assert n == len(view)
            self.buffer.clear()
            self._sent_buf = n
            self.index = 0
            if not future.done():
                future.set_result(n)
            logger.debug(f"first time call through on {self.socket}")
            return future
        loop.add_writer(self.socket.fileno(), functools.partial(self._send_message, future=future))
        self._task = future
        return future


@asynccontextmanager
async def open_connection(
    destination: AddressType,
    *,
    tls: ssl.SSLContext | None = None,
    default_tls_mode: Literal["auto", "off", "force"] = "auto",
) -> AsyncContextManager[Connection]:
    asyncio.get_running_loop()
    logger = logging.getLogger(f"{root_logger.name}.open_connection")
    async with AsyncExitStack() as stack:
        match destination:
            case http if isinstance((http := destination), HttpSocket) or (
                isinstance((http := destination), TcpSocket)
                and http.parsed_url.scheme in ("https", "http")
            ):
                http.query_parameters.setdefault("tls", (default_tls_mode,))

                tls_setting = None
                with suppress(KeyError, ValueError):
                    tls_setting = http.query_parameters["tls"][0].lower()
                match tls_setting:
                    case "off" | "0" | "no" | "n" | "false" | "f":
                        tls = None
                    case "auto" | "detect" | None:
                        if http.parsed_url.scheme == "https" or http.parsed_url.port == 443:
                            # perror('adding tls')
                            tls = ssl.create_default_context()
                        if tls is not None:
                            tls = (tls, "only-if-http")
                    case "force" if tls is None:
                        tls = ssl.create_default_context()
                    case _:
                        raise ValueError(tls_setting)

                match tls:
                    case ssl_context if isinstance(ssl_context, ssl.SSLContext):
                        reader, writer = await asyncio.open_connection(
                            destination.hostname, destination.port, ssl=ssl_context
                        )
                    case _:
                        reader, writer = await asyncio.open_connection(
                            destination.hostname, destination.port, ssl=None
                        )

            case tcp if isinstance((tcp := destination), TcpSocket):
                tls = None
                tcp.query_parameters.setdefault("tls", (default_tls_mode,))
                if tcp.parsed_url.scheme == "https" or tcp.parsed_url.port == 443:
                    # perror('adding tls')
                    tls = ssl.create_default_context()
                    with suppress(KeyError):
                        if tcp.query_parameters["tls"][0].lower() in (
                            "off",
                            "0",
                            "no",
                            "n",
                            "false",
                            "f",
                        ):
                            tls = None
                        elif tcp.query_parameters["tls"][0].lower() in (
                            "auto",
                            "detect",
                        ):
                            tls = (tls, "only-if-http")
                match tls:
                    case ssl_context if isinstance(ssl_context, ssl.SSLContext):
                        reader, writer = await asyncio.open_connection(
                            f"{destination.hostname}", destination.port, ssl=ssl_context
                        )
                    case _:
                        reader, writer = await asyncio.open_connection(
                            f"{destination.hostname}", destination.port, ssl=None
                        )
            case unix if isinstance((unix := destination), UnixSocket):
                if unix.type is socket.SOCK_STREAM:
                    reader, writer = await asyncio.open_unix_connection(f"{unix.file!s}")
                elif unix.type is socket.SOCK_DGRAM:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                    tmpdir = stack.enter_context(tempfile.TemporaryDirectory())
                    s.bind(f"{tmpdir}/{os.getpid()}.sock")
                    os.set_blocking(s.fileno(), False)
                    reader, writer = (
                        AsyncDatagramReader(unix, s),
                        AsyncDatagramWriter(unix, s),
                    )
                else:
                    assert_never(unix.type)
            case udp if isinstance((udp := destination), UdpSocket):
                s = socket.socket(destination.family, destination.type)
                s.bind(("", 0))
                s.connect((f"{udp.hostname!s}", udp.port))
                os.set_blocking(s.fileno(), False)
                logger.debug(f"connected to {udp.hostname!s}:{udp.port}")
                reader, writer = (
                    AsyncDatagramReader(udp, s),
                    AsyncDatagramWriter(udp, s),
                )
            case _:
                assert_never(destination)
        # perror('opened to', reader, writer, 'for', destination)
        yield Connection(destination, reader, writer, tls)


class HttpRequestLine(NamedTuple):
    method: str
    path: str
    version: Literal["HTTP/1.1", "HTTP/1.0"]


def maybe_http_request_line(b: bytes) -> None | HttpRequestLine:
    index = None
    with suppress(ValueError):
        index = b.index(b"\r\n")
        b = b[:index]
    method, path_and_version = b.split(b" ", 1)
    match method:
        case b"GET" | b"HEAD" | b"PUT" | b"POST" | b"PATCH" | b"TRACE" | b"DELETE":
            path, http_version = path_and_version.rsplit(b" ", 1)
            http_version = http_version.upper()
            return HttpRequestLine(method, path, http_version)
        case method if method.isalpha() and method.isupper():
            logger.warning(f"Unknown method: {method!r}")
            return None
        case _:
            return None


def first_or_null(items):
    with suppress(ValueError, TypeError, IndexError):
        return items[0]
    return None


class Proxy:
    def __init__(
        self,
        my_address: AddressType,
        sock: socket.socket,
        destination_address: AddressType,
    ):
        if my_address.type == socket.SOCK_DGRAM:
            my_address.query_parameters.setdefault("response-from", ("server-socket",))
        if destination_address.type == socket.SOCK_DGRAM:
            my_address.query_parameters.setdefault("response-from", ("server-socket",))

        assert first_or_null(my_address.query_parameters.get("response-from")) in (
            "server-socket",
            "new-socket",
            None,
        )
        self.address = my_address
        self._socket = sock
        self.destination = destination_address
        self.target = None
        if os.get_blocking(self._socket.fileno()):
            os.set_blocking(self._socket, False)
        self.buffer = bytearray(4096)
        self.length = 0
        self.is_close = False
        self.tasks = weakref.WeakSet()
        self.sessions = []

    async def check_destination(self):
        async with open_connection(self.destination):
            ...

    async def __aenter__(self):
        await self.check_destination()
        loop = asyncio.get_running_loop()
        self._done = loop.create_future()
        match self.address:
            case addr if isinstance(addr, UdpSocket) or addr.type == socket.SOCK_DGRAM:
                self.target = self.process_messages
            case _:
                self.target = self.accept_new_connections
        return self

    async def __aexit__(self, exc_type, exc, traceback): ...

    async def run_forever(self):
        loop = asyncio.get_running_loop()
        task = loop.create_task(self.target())
        task.set_name(f"{type(self).__name__}.{self.target.__name__}[loop]")
        await self._done
        if not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await task
        self.close()

    def stop(self):
        if not self._done.done():
            self._done.set_result(False)

    def close(self):
        self.is_closed = True
        if (sock := self._socket) is not None:
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with suppress(RuntimeError):
                loop = asyncio.get_running_loop()
                if loop.remove_reader(sock.fileno()):
                    pass
                if loop.remove_writer(sock.fileno()):
                    pass
            self._socket.close()
        self._socket = None

    async def accept_new_connections(self):
        try:
            async for session in self.iter_accepts():
                pass
                # perror('client', session)
                session.task.add_done_callback(
                    functools.partial(self.write_access_log, session=session)
                )
        except Exception:
            # perror('poop')
            traceback.print_exc()
        else:
            # perror('accept_new_connections', 'd=')
            ...

    async def process_messages(self):
        loop = asyncio.get_running_loop()
        message: Message
        async for message in self.iter_recvmsg():
            try:
                match message.from_address:
                    case (host, port) if isinstance(host, str) and isinstance(port, int) and (
                        host_ip := maybe_ipaddress(host)
                    ):
                        match response_from := first_or_null(
                            self.address.query_parameters["response-from"]
                        ):
                            case "new-socket":
                                client_sock = socket.socket(
                                    (
                                        socket.AF_INET6
                                        if isinstance(host_ip, IPv6Address)
                                        else socket.AF_INET
                                    ),
                                    socket.SOCK_DGRAM,
                                )
                                os.set_blocking(client_sock.fileno(), False)
                                dest = (f"{host_ip}", port)
                                logger.debug(f"connecting to client at {dest}")
                                match name := client_sock.getsockname():
                                    case (str(ip), 0) if ip in (
                                        "",
                                        "0.0.0.0",
                                        "::0",
                                        "::",
                                    ):
                                        client_sock.bind(("", 0))
                                    case _:
                                        logger.error(f"already bounded to {name}")
                                client_sock.connect(dest)
                                name = client_sock.getsockname()
                                logger.debug(f"connected to client at  <=> {name}")
                                request = UdpRequest.new(
                                    host,
                                    port,
                                    client_sock,
                                    self.address,
                                    client_sock.type,
                                )
                            case "server-socket":
                                request = UdpRequest.new(
                                    host,
                                    port,
                                    self._socket,
                                    self.address,
                                    self._socket.type,
                                )
                            case _:
                                assert_never(response_from)
                    case str(named_socket):
                        if named_socket:
                            client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                            os.set_blocking(client_sock.fileno(), False)
                            client_sock.connect(named_socket)
                            request = UnixRequest.new(
                                client_sock,
                                Path(named_socket),
                                self.address,
                                client_sock.type,
                            )
                        else:
                            raise NotImplementedError("anonymous messages not usable")
                    case _:
                        raise NotImplementedError(f"Unable to process {message.from_address}")
            except Exception:
                logger.exception("wtf")
                continue
            else:
                task = loop.create_task(self.handle_datagram_request(request, message))
                session = self.create_connection_for(request, task=task)
                session.task.add_done_callback(
                    functools.partial(self.write_access_log, session=session)
                )
                len(self.sessions)
                self.sessions.append(session)
                self.tasks.add(session.task)

    async def iter_accepts(self):
        try:
            while session := await self.accept():
                yield session
        except Exception:
            logger.exception("unhandled error")
            raise

    async def handle_datagram_request(self, request: UdpRequest | UnixRequest, message: Message):
        loop = asyncio.get_running_loop()
        this = asyncio.current_task()
        this.started_at = loop.time()
        logger.debug(f"UDP:handle_datagram_request:{request}")
        this.add_done_callback(
            functools.partial(is_errored, name=self.handle_datagram_request.__qualname__)
        )
        async with open_connection(self.destination) as remote_conn:
            await _write(remote_conn.writer, message.span)
            logger.debug(f"reading from {remote_conn.reader}")
            match remote_conn.reader:
                case AsyncDatagramReader():
                    message = await remote_conn.reader.recvmsg()
                    if message.events or message.flags:
                        logger.debug(
                            f"Message has additional features: {message.flags}, {message.events}"
                        )
                    response = message.span
                case _:
                    response = await remote_conn.reader.read()
            logger.debug(f"forwarding {bytes(response)} to {request.socket}")
            match request.server_address:
                case UdpSocket():
                    match first_or_null(request.server_address.query_parameters["response-from"]):
                        case "server-socket":
                            request.socket.sendto(
                                response, (request.remote_ip, request.remote_port)
                            )
                        case _:
                            request.socket.send(response)
                case _:
                    request.socket.send(response)

    async def handle_request(self, request: HttpRequest | TcpRequest | UnixRequest):
        loop = asyncio.get_running_loop()
        this = asyncio.current_task()
        this.started_at = loop.time()
        logger.debug(f"TCP:handle_request:{request}")
        this.add_done_callback(
            functools.partial(is_errored, name=self.handle_request.__qualname__)
        )

        copy_remote_to_client: asyncio.Task
        copy_client_to_remote: asyncio.Task
        front: bytes = b""

        async with open_connection(self.destination) as remote_conn:
            match remote_conn.tls:
                case (ssl_context, "only-if-http") if isinstance(ssl_context, ssl.SSLContext):
                    # ARJ: Read the first 200 bytes, if it's an HTTP/1 unecrypted conn,
                    # then ...
                    front = await request.read()
                    if match := maybe_http_request_line(front):
                        logger.info(f"Unencrypted {match.version}: {match.method} {match.path}")
                        await remote_conn.start_tls(
                            ssl_context, server_hostname=self.destination.hostname
                        )
                    else:
                        logger.warning("Encrypted client call, body opaque")
                        # await request.
                case None:
                    logger.info("not doing any encryption setup")
                case ssl_context if isinstance(ssl_context, ssl.SSLContext):
                    logger.info(f"Using encryption from {ssl_context!r}")
                case _:
                    pass
            copy_remote_to_client, copy_client_to_remote = (
                loop.create_task(
                    copy(f"{self.destination!s}", remote_conn.reader, request.response)
                ),
                loop.create_task(
                    copy(
                        f"{request.remote_addr}",
                        request,
                        remote_conn.writer,
                        prefix_bytes=front,
                    )
                ),
            )
            downloaded, uploaded = await asyncio.gather(
                copy_remote_to_client, copy_client_to_remote, return_exceptions=True
            )
            totals = None
            for item in (downloaded, uploaded):
                if isinstance(item, Exception):
                    e = item
                    traceback.print_exception(type(e), e, e.__traceback__)
                    continue
                elapsed, stats = item
        if totals is None:
            totals = stats
        else:
            totals = totals + stats
        return totals

    def write_access_log(self, fut: asyncio.Task, *, session: Session):
        loop = asyncio.get_running_loop()
        datetime.datetime.now(datetime.UTC)
        code = 200
        with suppress(asyncio.CancelledError):
            if fut.exception() is not None:
                code = 500
        access_log.info(
            f"[{loop.time() - fut.started_at:.2f}s] {code} [{session.request.scheme}] [remote-ip: {session.request.remote_addr}] [{session.request.server_address!s}]"
        )

    def create_connection_for(
        self, request: HttpRequest | TcpRequest | UnixRequest, *, task=None
    ) -> Session:
        loop = asyncio.get_running_loop()
        if task is None:
            task = loop.create_task(self.handle_request(request))
        return Session(request, task)

    def _remove_session(self, f: asyncio.Task, *, session):
        try:
            session.request.close()
        except Exception:
            perror("close diff")
        try:
            self.tasks.discard(session.task)
        except Exception:
            perror("unable to remove task")
        try:
            self.sessions.remove(session)
        except Exception:
            perror("unable to remove session")

    def accept(self, *, future: asyncio.Future | None = None):
        # perror('accept?')
        loop = asyncio.get_running_loop()
        try:
            with suppress(InterruptedError, BlockingIOError):
                client, addr = self._socket.accept()
                loop.remove_reader(self._socket.fileno())
                # perror('new client', client, addr)
                match self.address:
                    case address if isinstance(address, UnixSocket):
                        peer_pid = get_peer_pid(client)
                        if addr == "":
                            addr = UNNAMED_UNIX_SOCKET_ADDR.format(client.fileno(), peer_pid)
                        req = UnixRequest.new(
                            client, Path(addr), self.address, type=socket.SOCK_STREAM
                        )
                    case address if isinstance(address, TcpSocket):
                        client_addr, client_port = addr
                        req = TcpRequest.new(
                            client,
                            client_addr,
                            client_port,
                        )
                    case address if isinstance(address, HttpSocket):
                        req = HttpRequest.new(
                            client,
                            client_addr,
                            client_port,
                        )
                    case _:
                        assert_never(self.address)
                session = self.create_connection_for(req)
                len(self.sessions)
                self.sessions.append(session)
                self.tasks.add(session.task)

                session.task.add_done_callback(
                    functools.partial(self._remove_session, session=session)
                )
                if future is not None and not future.done():
                    future.set_result(session)
                return session
        except Exception as e:
            if future is not None and not future.done():
                future.set_exception(e)
            raise
        f = loop.create_future()
        loop.add_reader(self._socket.fileno(), functools.partial(self.accept, future=f))
        return f

    async def iter_recvmsg(self, size=-1):
        try:
            logger.debug(f"recv meg on {self._socket}")
            while message := recvmsg_into(self._socket, self.buffer):
                message = await message
                logger.debug(f"Got {message}!")
                yield message
        except Exception:
            logger.exception("wtf")
            raise


class UnknownAncilliaryMessage(NamedTuple):
    cmsg_level: int
    cmsg_type: int
    cmsg_data: bytes


def recvmsg_into(
    s: socket.socket, buffer: memoryview | bytearray, /, flags=0, *, future=None
) -> Awaitable[Message]:
    buf = memoryview(buffer)
    loop = asyncio.get_running_loop()
    if future is None:
        future = loop.create_future()
    else:
        logger.debug(f"using {future}")
    with suppress(InterruptedError, BlockingIOError):
        (
            nbytes,
            ancdata,
            msg_flags,
            address,
        ) = s.recvmsg_into([buf], 4096, flags)
        assert nbytes <= len(buf)
        logger.debug(
            f"UDP read of {nbytes!r} from {address!r} with flags {msg_flags!r} and ancdata = {ancdata!r}"
        )
        events = []
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            view = memoryview(cmsg_data)
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                # Append data, ignoring any truncated integers at the end.
                for fd in (view[: len(view) - (len(view) % struct.calcsize("I"))]).cast("I"):
                    assert isinstance(fd, int)
                    events.append(SharedFileDescriptor.new(fd))
            else:
                events.append(UnknownAncilliaryMessage(cmsg_level, cmsg_type, cmsg_data))
        if not future.done():
            future.set_result(Message.new(0, buf[0:nbytes], msg_flags, address, tuple(events)))
        return future
    # perror('blocked?')
    loop.add_reader(s.fileno(), functools.partial(recvmsg_into, future=future), s, buffer, flags)
    return future


def parse_address(
    s: str, *, is_local_host=False
) -> Literal[ALL_INTERFACES] | tuple[IPv4Address | IPv6Address | str, int] | Path:
    if ":" in s:
        if "]" in s:
            if s.rindex("]") < s.rindex(":"):
                maybe_host, maybe_port = s.rsplit(":", 1)
            else:
                maybe_host = s
                maybe_port = -1
        else:
            maybe_host, maybe_port = s.rsplit(":", 1)
        try:
            port = int(maybe_port or -1)
        except ValueError:
            ...
        else:
            my_address: Literal[ALL_INTERFACES] | IPv6Address | IPv4Address | str
            match maybe_host:
                case address if (address := maybe_ipaddress(maybe_host)) is not None:
                    my_address = address
                    if int(address) == 0:
                        my_address = ALL_INTERFACES
                case domain if (match := DOMAIN_REGEX.fullmatch(domain)) is not None:
                    tld = match.groupdict()["tld"]
                    if tld == "localhost":
                        my_address = domain
                    else:
                        if is_local_host:
                            perror(f"Warning: {domain!r} is possibly not localhost")
                        my_address = domain
                case parsed_url if (parsed_url := urlsplit(maybe_host)):
                    my_address = None
                    logger.debug(
                        f"Not a domain: {parsed_url.scheme}://{parsed_url.netloc}/{parsed_url.path}"
                    )
                case "":
                    my_address = ALL_INTERFACES
                case _:
                    raise ValueError(f"Cannot parse {maybe_host}")
            if my_address is not None:
                return TcpSocket.new(my_address, port)
    match parsed_url := urlsplit(s):
        case ("unix", "", path, query, _) if path:
            return UnixSocket.new(path, query)
        case ("unix+udp", "", path, query, _) if path:
            s = UnixSocket.new(path, query, default_type=socket.SOCK_DGRAM)
            s.query_parameters.setdefault("response-from", ("server-socket",))
            return s
        case ("https" | "http", netloc, path, query, _) if netloc:
            if parsed_url.port:
                return HttpSocket.new(parsed_url.hostname, parsed_url.port, parsed_url)
            if parsed_url.scheme == "https":
                return HttpSocket.new(parsed_url.hostname, 443, parsed_url)
            return HttpSocket.new(parsed_url.hostname, 80, parsed_url)
        case ("udp", netloc, path, query, _) if netloc:
            if parsed_url.port:
                return UdpSocket.new(parsed_url.hostname, parsed_url.port, parsed_url)
            raise ValueError("Unable to determine port for udp protocol!")
        case ("udp", _, path, query, _) if netloc == "" and path:
            return UnixSocket.new(path, query, default_type=socket.SOCK_DGRAM)
        case ("unix+udp", _, path, query, _) if netloc == "" and path:
            s = UnixSocket.new(path, query, default_type=socket.SOCK_DGRAM)
            s.query_parameters.setdefault("response-from", ("server-socket",))
            return s
        case (proto, netloc, path, query) if netloc:
            if not parsed_url.port:
                raise ValueError(f"Unable to determine port for {proto!r}")
            return TcpSocket.new(parsed_url.hostname, parsed_url.port, parsed_url)
        case _:
            raise ValueError("Unknown ")


async def main(
    my_address,
    their_address,
    request_headers: list[tuple[str, str]] | dict[str, str] | None = None,
):
    async with proxy_between(
        parse_address(my_address, is_local_host=True), parse_address(their_address)
    ) as proxy:
        if isinstance(proxy.destination, HttpSocket) and request_headers is not None:
            proxy.set_request_headers(request_headers)
        try:
            await proxy.run_forever()
        except (KeyboardInterrupt, SystemExit) as e:
            raise e from None


async def _track_future_status(future: asyncio.Future, after_s: int = 60):
    loop = asyncio.get_running_loop()

    async def thunk():
        return await future

    task = loop.create_task(thunk())
    t_s = loop.time()

    while not task.done():
        try:
            await asyncio.wait_for(asyncio.shield(task), after_s)
        except asyncio.TimeoutError:
            if not task.done():
                logger.warning(
                    f"{future!r} has taken longer than {after_s} (elapsed: {loop.time() - t_s}s)"
                )
        else:
            assert task.done()
            # it breaks here by default


async def write_pipe(
    fd: int,
    b: bytes | memoryview | bytearray,
    /,
    *,
    loop: asyncio.AbstractEventLoop | None = None,
) -> int:
    if loop is None:
        loop = asyncio.get_running_loop()
    future_or_written_bytes = _write_pipe_impl(fd, b, loop=loop)

    match future_or_written_bytes:
        case Awaitable():
            num_written = await future_or_written_bytes
            assert isinstance(
                num_written, int
            ), f"expected int, got {num_written!r} ({type(num_written)!r})!"
            return num_written
        case int(num_written):
            return num_written
        case _:
            assert_never(future_or_written_bytes)


def _write_pipe_impl(
    fd: int,
    b: bytes | bytearray | memoryview,
    /,
    *,
    loop: asyncio.AbstractEventLoop | None,
    future: asyncio.Future | None = None,
    offset: int = 0,
    monitor_task: asyncio.Task
    | None = None,  # task that writes to an err log for long-lived connections
) -> int | asyncio.Future:
    if loop is None:
        loop = asyncio.get_running_loop()
    try:
        n: int = os.write(fd, b)
    except (InterruptedError, BlockingIOError):
        if future is None:
            future = loop.create_future()
        if monitor_task is None:
            monitor_task = loop.create_task(_track_future_status(future, after_s=5))
        loop.add_writer(
            fd,
            functools.partial(
                _write_pipe_impl,
                loop=loop,
                future=future,
                offset=offset,
                monitor_task=monitor_task,
            ),
            fd,
            b,
        )
        future.add_done_callback(functools.partial(_write_pipe_on_done, loop, fd))
        logger.warning(
            f"{_write_pipe_impl} added future on_write for fd {fd} with buf len ({len(b)})"
        )
        return future
    else:
        if n == len(b):
            if future is not None and not future.done():
                future.set_result(n + offset)
            return n + offset
        if future is None:
            future = loop.create_future()
        assert not future.done()
        remainder = b[n:]  # the parts we still have yet to write to ....
        assert len(remainder) > 0, "remainder must be non-empty"
        logger.warning(
            f"{_write_pipe_impl.__name__} wrote {n} bytes to {fd} ({len(remainder)} bytes left to go....)"
        )
        if monitor_task is None:
            monitor_task = loop.create_task(_track_future_status(future, after_s=5))
        loop.add_writer(
            fd,
            functools.partial(
                _write_pipe_impl,
                loop=loop,
                future=future,
                offset=offset + n,
                monitor_task=monitor_task,
            ),
            fd,
            remainder,
        )
        future.add_done_callback(functools.partial(_write_pipe_on_done, loop, fd))

        # loop.add_writer(fd, _write_pipe_impl, , offset=n + offset, future=future, loop=loop, monitor_task=monitor_task)
        # future.add_done_callback(functools.partial(_write_pipe_on_done, loop, fd))
        return future


def _write_pipe_on_done(
    loop: asyncio.AbstractEventLoop,
    fd: int,
    fut: asyncio.Future,
):
    if not loop.remove_writer(fd):
        logger.error(f"Spurious loop.remote_writer callback on pipe fd {fd}")


def close_pipe(fd: int, task: asyncio.Task | None | asyncio.Future = None):
    logger.debug(f"Closing pipe on behalf of {task!r}")
    os.close(fd)


async def _write_stream_to_pipe(fd: int, buf: Buffer): ...


def try_fileno(item):
    match item:
        case int(fd) if fd > -1:
            return fd
        case int():
            assert fd < 0
            raise ValueError("value fd may not be negative!")
        case fileno_able if callable(getattr(fileno_able, "fileno", None)):
            with suppress(io.UnsupportedOperation):
                fd = item.fileno()
                if fd > -1:
                    return fd
                raise TypeError(f"fd {fd!r} is negative?!")
            return None
        case _:
            return None


class ContainsFileDescriptor(Protocol):
    def fileno(self) -> int: ...


def has_fileno(item) -> TypeGuard[ContainsFileDescriptor]:
    with suppress(AttributeError, io.UnsupportedOperation):
        return item.fileno() > -1
    return False


def expect_heritable(file: int | ContainsFileDescriptor) -> None:
    fileno_able: ContainsFileDescriptor

    match file:
        case int(fd) if fd > -1:
            ...
        case fileno_able if has_fileno(fileno_able):
            fd = fileno_able.fileno()
        case _:
            raise TypeError(f"{fd} is invalid fd!")
    try:
        if os.get_inheritable(fd) is False:
            logger.warning(f"[{expect_heritable.__name__}] stdin={fd} (fd) is not heritable!")
            os.set_inheritable(fd, True)
    except OSError as exc:
        perror(exc.errno)
        raise


async def ensure_task_scheduled(
    task: asyncio.Task, *tasks: asyncio.Task, loop: asyncio.AbstractEventLoop | None = None
):
    if loop is None:
        loop = asyncio.get_running_loop()
    tasks = (task, *tasks)
    del task
    wake_up_tasks = []
    for task in tasks:
        if not task.done():
            wake_up_tasks.append(loop.create_task(asyncio.wait_for(asyncio.shield(task), 0.1)))
    if wake_up_tasks:
        results = await asyncio.gather(*wake_up_tasks, return_exceptions=True)
        for task, result_or_exception in zip(wake_up_tasks, results):
            match result_or_exception:
                case asyncio.TimeoutError():
                    pass
                case Exception():
                    logger.exception(
                        "Trying to ensure a task schedule faulted!",
                        exc_info=result_or_exception,
                    )
                case _:
                    pass
    return tasks


class Readable(Protocol):
    def read(self):
        pass


def is_readable(item) -> TypeGuard[Readable]:
    read_thunk = getattr(item, "read", None)
    match read_thunk:
        case func if callable(func):
            return True
        case _:
            return False


type IntoStdin = (
    Buffer
    | ContainsFileDescriptor
    | int
    | Literal[asyncio.subprocess.PIPE, asyncio.subprocess.DEVNULL, asyncio.subprocess.STDOUT]
)


async def copy_stream_into(
    write_pipe_fd: int, stream_or_buffer: Buffer | Readable | asyncio.StreamReader
):
    if os.get_blocking(write_pipe_fd) is True:
        os.get_blocking(write_pipe_fd, False)
    match stream_or_buffer:
        case Buffer():
            with memoryview(stream_or_buffer) as buffer:
                await write_pipe(write_pipe_fd, buffer)
        case asyncio.StreamReader():
            reader = stream_or_buffer
            while (buf := await reader.read()) != b"":
                await write_pipe(write_pipe_fd, buf)
        case readable_obj if is_readable(readable_obj):
            while (buf := readable_obj.read()) != b"":
                if isinstance(buf, Awaitable):
                    buf = await buf
                    assert isinstance(buf, Buffer)
                    if buf == b"":
                        break

            # done with copying


async def read_pipe_fd_for(
    *readers: asyncio.StreamReader,
    loop: asyncio.AbstractEventLoop | None = None,
) -> tuple[int, tuple[asyncio.Task, ...]]:
    """
    Copy the output from N readers (at least 1) to be read by the user
    of this read-only fd
    """
    if loop is None:
        loop = asyncio.get_running_loop()
    this = asyncio.current_task()
    this.set_name(f"[{read_pipe_fd_for.__name__}]copy")
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, False)
    os.set_blocking(write_fd, False)
    expect_heritable(read_fd)

    new_tasks = []
    for index, reader in enumerate(readers):
        task = loop.create_task(copy_stream_into(write_fd, reader))
        task.set_name(f"copy-stream-reader-into-pipefd[{index}]")
        new_tasks.append(task)
    tasks = await ensure_task_scheduled(*new_tasks, loop=loop)
    return read_fd, tasks


Executable = NewType("Executable", Path)


@functools.lru_cache(100)
def locate_binary(
    name: str,
    /,
    search_paths: tuple[Path, ...] | None = None,
    *,
    environ=None,
) -> Executable:
    if environ is None:
        environ = os.environ
    if search_paths is None:
        try:
            environ_paths = environ["PATH"]
        except KeyError:
            raise ValueError("Provided environment lacks PATH!") from None
        else:
            search_paths = tuple(
                path
                for x in environ_paths.split(":")
                if os.path.exists(x) and (path := Path(x)).is_dir()
            )
    if not search_paths:
        raise ValueError("Empty search_paths!")
    candidates = []
    seen = set()
    for folder in (
        path
        for folder_path in os.environ["PATH"].split(":")
        if os.path.exists(folder_path) and (path := Path(folder_path)).is_dir()
    ):
        cache_key = folder.resolve(True)
        if cache_key in seen:
            continue
        seen.add(cache_key)
        if (file := folder / name).exists() and file.is_file():
            candidates.append(file)
            if (executable := may_execute_file(file)) is not None:
                return executable
    e = FileNotFoundError(name)
    e.partial_matches = tuple(candidates)
    raise e


def may_execute_file(binary: Path) -> Executable | None:
    group_ids = os.getgroups()
    uids = (os.getuid(), os.geteuid())
    match binary:
        case binary if (file_stat := binary.stat()).st_mode & stat.S_IXUSR and (
            is_owner := file_stat.st_uid in uids
        ):
            return Executable(binary)
        case binary if file_stat.st_mode & stat.S_IXGRP and (
            is_group_member := file_stat.st_gid in group_ids
        ):
            return Executable(binary)
        case binary if file_stat.st_mode & stat.S_IXOTH and not any((is_owner, is_group_member)):
            return Executable(binary)
        case _:
            return None


async def create_subprocess_exec(
    program: str | Path,
    *args: str,
    stdin: IntoStdin | None | asyncio.subprocess.Process = None,
    loop: asyncio.AbstractEventLoop | None = None,
    **kwargs,
) -> asyncio.subprocess.Process:
    """
    A async subprocess exec that can:
        - automatically allocate a pipe to send
            bytes, AsyncReader, **ANOTHER asyncio.subprocess.Process**, file objs
            to the subprocess on stdin
        - tries best effort to drain from an os.pipe and can reschedule on full pipes using asyncio
    """
    match program:
        case Path():
            if program.parent == Path("."):
                program = locate_binary(program)
            else:
                program = program.resolve(True)
                if may_execute_file(program) is None:
                    raise PermissionError(f"Unable to execute {program!r}")
        case str():
            file = Path(program)
            if file.parent == Path("."):
                program = locate_binary(program)
            else:
                program = file.resolve(True)
                if may_execute_file(program) is None:
                    raise PermissionError(f"Unable to execute {program!r}")
        case _:
            raise TypeError(f"program is expected to be str or Path, not {type(program)!r}")

    if loop is None:
        loop = asyncio.get_running_loop()

    this: asyncio.Task = asyncio.current_task()

    kwargs.setdefault("stderr", asyncio.subprocess.PIPE)
    kwargs.setdefault("stdout", asyncio.subprocess.PIPE)
    tasks: None | tuple[asyncio.Task, ...] = None

    task: asyncio.Task
    source_process: asyncio.subprocess.Process
    buffer: Buffer
    match stdin:
        case asyncio.subprocess.Process() if (source_process := stdin) is not None:
            del stdin
            proxied_stdin, tasks = await read_pipe_fd_for(source_process.stdout, loop=loop)
            assert isinstance(proxied_stdin, int)
            assert expect_heritable(proxied_stdin)
            await ensure_task_scheduled(*tasks, loop=loop)
        case asyncio.StreamReader() if (reader := stdin) is not None:
            del stdin
            proxied_stdin, tasks = await read_pipe_fd_for(reader, loop=loop)
            assert isinstance(proxied_stdin, int)
            assert expect_heritable(proxied_stdin)
            await ensure_task_scheduled(*tasks, loop=loop)
        case Buffer() | io.BytesIO() if (
            buffer := stdin.getbuffer() if isinstance(stdin, io.BytesIO) else stdin
        ) is not None:
            del stdin
            read_fd, write_fd = os.pipe()
            logger.debug(f"Converting buffer of {len(buffer)} to a pipe[{read_fd}, {write_fd}]")
            logger.debug(f"assigning stdin to read pipe fd {read_fd}")
            os.set_inheritable(write_fd, False)
            os.set_blocking(write_fd, False)
            expect_heritable(read_fd)
            task = loop.create_task(write_pipe(write_fd, buffer))
            tasks = (task,)
            task.set_name(f"Copying[{buffer[:120]}:{len(buffer)}]->fd:{write_fd}")
            task.add_done_callback(functools.partial(close_pipe, write_fd))
            await ensure_task_scheduled(task, loop=loop)
            # ARJ: ensure our side is closed for the read_fd to return b"" when subprocess is done...
            this.add_done_callback(functools.partial(close_pipe, read_fd))
            proxied_stdin = read_fd
        case _:
            proxied_stdin = stdin
            del stdin
    process = await asyncio.create_subprocess_exec(
        f"{program!s}", *args, stdin=proxied_stdin, **kwargs
    )
    if tasks is not None:
        process._tasks = tasks
    return process


async def make_ca_private_key() -> bytes:
    proc = await create_subprocess_exec(
        *shlex.split("openssl genrsa 4096"),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
    )
    private_key, error = await proc.communicate()
    if error:
        logger.debug(f"{make_ca_private_key.__name__} threw error {error}")
    assert private_key
    match proc.returncode:
        case int(code) if code != 0:
            raise ValueError(f"{error.decode()}")
        case 0:
            assert private_key
            return private_key
        case _:
            assert_never(proc.returncode)


async def make_ca_certificate_from_key(
    private_key_stream: io.BufferedIOBase | io.RawIOBase | Buffer,
) -> bytes:
    private_key = None
    match private_key_stream:
        case Buffer():
            private_key = private_key_stream
            del private_key_stream
        case io.BufferedIOBase() | io.RawIOBase():
            private_key = private_key_stream.read()
            assert private_key_stream.read() == b""
            assert isinstance(private_key, (bytes, str))
            if isinstance(private_key, str):
                private_key = private_key.encode()
            del private_key_stream
        case readable_obj if is_readable(readable_obj):
            private_key = private_key_stream.read()
            assert private_key_stream.read() == b""
            assert isinstance(private_key, (bytes, str))
            if isinstance(private_key, str):
                private_key = private_key.encode()
            del private_key_stream

    asyncio.get_running_loop()
    domain = os.uname().nodename
    with suppress(ValueError):
        _, domain = domain.split(".", 1)
    proc = await create_subprocess_exec(
        *shlex.split(
            "openssl req -passin pass: -passout pass: "
            f"-new -x509 -days 3062 -subj '/CN={domain}' "
            f'-addext "subjectAltName=DNS:localhost,DNS:*.localhost,DNS:*.local,DNS:{domain},DNS:*.{domain}" '
        ),
        stdin=private_key or private_key_stream,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    root_ca_certificate, stderr = await proc.communicate()
    if proc.returncode:
        raise ValueError(
            f"error: {stderr.decode().strip() or root_ca_certificate.decode().strip()}"
        )
    assert root_ca_certificate
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=root_ca_certificate.decode())
    return RootCertificate(root_ca_certificate, private_key or private_key_stream)


async def create_signed_cert_for(
    *domains,
    private_ca_key,
    public_ca_certificate: RootCertificate,
) -> tuple[bytes, bytes]:
    assert isinstance(public_ca_certificate, RootCertificate)
    common_name, *_ = domains
    if common_name.startswith(("DNS:", "IP:")):
        _, common_name = common_name.split(":", 1)
    alt_names = []
    for domain in domains:
        domain = domain.strip()
        if domain.upper().startswith(("IP:", "DNS:")):
            alt_names.append(domain)
            continue
        with suppress(ValueError):
            addr = ip_address(domain)
            ip_alt_name = f"IP:{str(addr) if isinstance(addr, IPv4Address) else f'[{addr!s}]'}"
            alt_names.append(ip_alt_name)
            continue
        alt_names.append(f"DNS:{domain}")
    alt_names = ",".join(alt_names)
    with tempfile.TemporaryDirectory() as tmp, tempfile.NamedTemporaryFile(
        "w+b"
    ) as private_ca_stream, tempfile.NamedTemporaryFile(
        "w+b"
    ) as public_ca_certificate_stream, tempfile.NamedTemporaryFile("w+b") as csr_request_stream:
        tmp = Path(tmp)
        proc = await create_subprocess_exec(
            *shlex.split(
                "openssl req -new -nodes -newkey rsa:4096 -sha256 "
                f" -keyout {tmp!s}/{common_name}.key "
                f'-subj "/CN={common_name}" '
                f'-addext "subjectAltName={alt_names}" '.strip()
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        common_csr, stderr = await proc.communicate()
        if stderr:
            logger.warning(f"got {stderr.decode()}")
        assert common_csr
        csr_request_stream.write(common_csr)
        csr_request_stream.flush()
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=public_ca_certificate.certificate)
        private_ca_stream.write(private_ca_key)
        public_ca_certificate_stream.write(public_ca_certificate.raw_certificate)
        private_ca_stream.flush()
        public_ca_certificate_stream.flush()
        assert os.stat(public_ca_certificate_stream.name).st_size
        assert os.stat(private_ca_stream.name).st_size
        # perror('my csr is', common_csr)
        cmd = (
            "openssl x509 -req "
            f"-in {csr_request_stream.name} "
            f"-signkey {private_ca_stream.name} "
            # f"-CA {public_ca_certificate_stream.name} -CAkey {private_ca_stream.name} "
            # "-CAcreateserial  "
            "-days 30 -sha256 "
        )
        # perror(cmd)
        proc = await create_subprocess_exec(
            *shlex.split(cmd.strip()),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=common_csr,
        )
        common_name_certificate, stderr = await proc.communicate()
        if stderr:
            logger.warning(f"got cert errs {stderr.decode()}")

        with open(tmp / f"{common_name}.key", "rb") as fh:
            common_name_private_key = fh.read()
        assert common_name_certificate
        assert common_name_private_key
        # perror(f"Create certificate for {domains} (crt: {len(common_name_certificate)}, private: {len(common_name_private_key)})")
        return TLSCertificate(common_name_certificate, common_name_private_key)


class ListFlags(IntFlag):
    INTERNAL = 1
    EXTERNAL = 2


def list_ips(flags: ListFlags = ListFlags.INTERNAL | ListFlags.EXTERNAL) -> tuple[IPAddress, ...]:
    seen = set()
    for address in (
        addr
        for row in socket.getaddrinfo(socket.gethostname(), None)
        for ip in row[4]
        if (addr := ip_address(ip)) and int(addr) > 0
    ):
        if address in seen:
            continue
        seen.add(addr)
        match attr_map := (addr.is_private, addr.is_global, addr.is_unspecified, addr.is_reserved):
            case (True, False, False, False) if flags & ListFlags.INTERNAL:
                yield addr
            case (False, True, False, False) if flags & ListFlags.EXTERNAL:
                yield addr
            case (_, _, _, True, _) | (_, _, _, True):
                logger.debug(f"ignored {addr}")
                continue
            case _:
                logger.debug(f"oops {addr} -> {attr_map}")


if __name__ == "__main__":
    import argparse

    logging.basicConfig()
    logger.setLevel(logging.INFO)
    access_log.setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.set_defaults(tls=None)
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    excl = parser.add_mutually_exclusive_group()
    excl.add_argument(
        "--tls",
        action="store_true",
        default=None,
        help="bootstrap a private CA and sign certs for localhost if necessary",
        dest="tls",
    )
    excl.add_argument("--no-tls", action="store_false", dest="tls")
    group = parser.add_argument_group("TLS options")
    group.add_argument(
        "--tls-certificate",
        type=argparse.FileType("rb"),
        default=None,
        dest="tls_certificate",
    )
    group.add_argument(
        "--tls-private-key",
        type=argparse.FileType("rb"),
        default=None,
        dest="tls_private_key",
    )
    group.add_argument(
        "--tls-root-ca-key",
        type=argparse.FileType("rb"),
        default=None,
        dest="tls_root_ca_key",
    )
    group.add_argument(
        "--tls-root-ca-certificate",
        type=argparse.FileType("rb"),
        default=None,
        dest="tls_root_ca_certificate",
    )
    parser.add_argument(
        "my_address", type=str, help="can be domain:port, proto://domain:port, et al."
    )
    parser.add_argument("--tls-save-home", default=None, type=Path)
    parser.add_argument("their_address", type=str)

    parser.set_defaults(headers=[])
    subcommands = parser.add_subparsers()
    mitm = subcommands.add_parser("mitm")
    mitm.add_argument(
        "-H", "--inject-header", type=str, default=[], action="append", dest="headers"
    )

    args = parser.parse_args()
    if args.tls is None:
        args.tls = any(
            (
                args.tls_certificate,
                args.tls_private_key,
                args.tls_root_ca_key,
                args.tls_root_ca_certificate,
                args.tls_save_home,
            )
        )
    ctx = ssl.create_default_context()
    ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    private_key: bytes
    certificate: bytes

    match (args.tls_root_ca_key, args.tls_root_ca_certificate):
        case (None, None):
            if args.tls:
                private_key = asyncio.run(make_ca_private_key())
                certificate = asyncio.run(make_ca_certificate_from_key(private_key))
                logger.info("created tls Root CA/key")
                match tls_save_home := args.tls_save_home:
                    case Path():
                        try:
                            tls_save_home.mkdir(exist_ok=True)
                        except FileExistsError:
                            logger.error(f"{tls_save_home!s} is not a directory!")
                            raise
                        with open(tls_save_home / "CA.key", "wb") as fh:
                            fh.write(private_key)
                        with open(tls_save_home / "CA.crt", "wb") as fh:
                            fh.write(certificate.raw_certificate)
            else:
                private_key = certificate = None

        case (private_key_stream, None):
            assert private_key_stream is not None
            private_key = private_key_stream.read()
            certificate = asyncio.run(make_ca_certificate_from_key(private_key))
            assert certificate

        case (None, certificate_stream):
            assert certificate_stream is not None
            raise ValueError("Missing --tls-root-ca-key")

        case (private_key_stream, certificate_stream):
            private_key = private_key_stream.read()
            certificate = certificate_stream.read()

        case _:
            assert_never((args.tls_root_ca_key, args.tls_root_ca_certificate))

    match (private_key, certificate):
        case (None, None):
            ...
        case (b"", b""):
            raise ValueError(
                f"{args.tls_root_ca_key.name} and {args.tls_root_ca_certificate.name} are both empty!"
            )
        case (bytes(private_key), bytes(certificate)) if all((private_key, certificate)):
            logger.debug(f"Loading root CA with private key {len(private_key)} length")
            ctx.load_verify_locations(cadata=certificate.decode())
        case _:
            if not private_key:
                raise ValueError("root ca private key missing")
            if not certificate:
                raise ValueError("root ca private certificate missing")
    args.tls_root_ca_key = private_key
    args.tls_root_ca_certificate = certificate

    del private_key, certificate

    match (args.tls_private_key, args.tls_certificate):
        case (None, None):
            private_key_stream = certificate_stream = None
        case (private_key_stream, None):
            assert private_key_stream is not None
            raise ValueError("Missing --tls-certificate!")
        case (None, certificate_stream):
            assert certificate_stream is not None
            raise ValueError("Missing --tls-private-key")
        case (private_key_stream, certificate_stream):
            assert all((private_key_stream, certificate_stream))
            private_key = private_key_stream.read()
            private_key_stream.seek(0)
            certificate = certificate_stream.read()
            certificate_stream.seek(0)
            if not private_key:
                private_key_stream = None
            if not certificate:
                certificate_stream = None
            assert isinstance(private_key, bytes)
            assert isinstance(certificate, bytes)
        case _:
            assert_never((args.tls_private_key, args.tls_certificate))

    match (private_key_stream, certificate_stream):
        case (None, None) | (b"", b""):
            if args.tls:
                tls_private_key, tls_certificate = asyncio.run(
                    create_signed_cert_for(
                        "DNS:proxy9.localhost",
                        f"DNS:{os.uname().nodename}",
                        private_ca_key=args.tls_root_ca_key,
                        public_ca_certificate=args.tls_root_ca_certificate,
                    )
                )
                match tls_save_home := args.tls_save_home:
                    case Path():
                        try:
                            tls_save_home.mkdir(exist_ok=True)
                        except FileExistsError:
                            logger.error(f"{tls_save_home!s} is not a directory!")
                            raise
                        with open(tls_save_home / f"{os.uname().nodename}.key", "wb") as fh:
                            fh.write(tls_private_key)
                        with open(tls_save_home / f"{os.uname().nodename}.crt", "wb") as fh:
                            fh.write(tls_certificate)

                logger.info(f"created tls certificate/key for {os.uname().nodename}")
            else:
                tls_private_key = tls_certificate = None
        case (private_key_stream, certificate_stream):
            assert all(x is not None for x in (private_key_stream, certificate_stream))
            match private_key := private_key_stream.read():
                case b"":
                    raise ValueError(f"{private_key_stream.name!r} is empty!")
                case bytes():
                    pass
                case _:
                    raise TypeError(
                        f"Unknown type {private_key_stream!r} ({type(private_key_stream).__name__})"
                    )
            match certificate := certificate_stream.read():
                case b"":
                    raise ValueError(f"{certificate_stream.name!r} is empty!")
                case bytes():
                    pass
                case _:
                    raise TypeError(f"Unknown type {certificate!r} ({type(certificate).__name__})")
            assert private_key
            assert certificate

    headers = []
    for index, header in enumerate(args.headers):
        key, value = (x.strip() for x in header.split(":", 1))
        headers.append((key, value))

    if args.debug:
        logger.setLevel(logging.DEBUG)

    with asyncio.Runner() as runner:
        runner.run(main(args.my_address, args.their_address, request_headers=headers or None))
