from __future__ import annotations

import datetime
import ipaddress
import logging
import socket
import sys
from contextlib import ExitStack
from enum import IntFlag
from typing import (
    NamedTuple,
)

import cffi
from namedtuple_support import EnhancedSerialize, Serialization

try:
    from _ip_support import lib, ffi
except ImportError:
    from ip_support_builder import main

    main()
    from _ip_support import lib, ffi

logger = logging.getLogger(__name__)


def _free_ifaddr_on(container):
    assert ffi.typeof(container) is ffi.typeof("struct ifaddrs **")
    lib.freeifaddrs(container[0])


def _iterate_ifaddr(element):
    assert ffi.typeof(element) is ffi.typeof("struct ifaddrs*")
    yield element
    while (element := element.ifa_next) != ffi.NULL:
        assert ffi.typeof(element) is ffi.typeof("struct ifaddrs   *")
        assert ffi.typeof(element.ifa_addr) is ffi.typeof("struct sockaddr  *")
        yield element


class InterfaceFlags(IntFlag):
    UP = lib.IFF_UP
    BROADCAST = lib.IFF_BROADCAST
    DEBUG = lib.IFF_DEBUG
    LOOPBACK = lib.IFF_LOOPBACK
    POINTOPOINT = lib.IFF_POINTOPOINT
    RUNNING = lib.IFF_RUNNING
    NOARP = lib.IFF_NOARP
    PROMISC = lib.IFF_PROMISC
    ALLMULTI = lib.IFF_ALLMULTI
    OACTIVE = lib.IFF_OACTIVE
    SIMPLEX = lib.IFF_SIMPLEX
    LINK0 = lib.IFF_LINK0
    LINK1 = lib.IFF_LINK1
    LINK2 = lib.IFF_LINK2
    MULTICAST = lib.IFF_MULTICAST
    NOTRAILERS = lib.IFF_NOTRAILERS


def _listifaddrs(*, allocator: cffi.FFI | None = None):
    if allocator is None:
        allocator = ffi
    with ExitStack() as stack:
        if_list_ptr = stack.enter_context(allocator.new("struct ifaddrs **"))
        lib.getifaddrs(if_list_ptr)
        head = if_list_ptr[0]
        stack.callback(lib.freeifaddrs, head)
        yield from _iterate_ifaddr(head)


ifdata_ctype = ffi.typeof("struct if_data")
if_data_cls = NamedTuple(
    "if_data",
    **{key: int for key in (field[0] for field in ifdata_ctype.fields)},
)


HardwareEthernet = str


def list_interfaces(*, allocator=None):
    if allocator is None:
        allocator = ffi
    interfaces_by_name: dict[str, list] = {}
    for element in _listifaddrs(allocator=allocator):
        name = ffi.string(element.ifa_name).decode()
        family = socket.AddressFamily(element.ifa_addr.sa_family)
        flags = element.ifa_flags
        ip = None
        match family:
            case socket.AF_INET6 if element.ifa_addr != ffi.NULL:
                inet6_struct = ffi.cast("struct sockaddr_in6*", element.ifa_addr)
                with memoryview((buffer := ffi.buffer(inet6_struct.sin6_addr))) as view:
                    ip = ipaddress.ip_address(view.tobytes())
                    assert isinstance(ip, ipaddress.IPv6Address)
                del buffer
            case socket.AF_INET if element.ifa_addr != ffi.NULL:
                inet = ffi.cast("struct sockaddr_in*", element.ifa_addr)
                with memoryview((buffer := ffi.buffer(inet.sin_addr))) as view:
                    ip = ipaddress.ip_address(view.tobytes())
                    assert isinstance(ip, ipaddress.IPv4Address)
                del buffer
            case socket.AF_LINK if element.ifa_addr != ffi.NULL:
                cdata = ffi.cast("struct sockaddr_dl *", element.ifa_addr)
                interface_index = -1
                if cdata.sdl_index != 0:
                    interface_index = cdata.sdl_index

                length = cdata.sdl_len
                block = ffi.cast("char*", cdata)
                buf = ffi.buffer(block, length)
                view = memoryview(buf)
                assert len(view) == length
                cdata = ffi.from_buffer("struct sockaddr_dl *", view)
                index = ffi.offsetof("struct sockaddr_dl *", "sdl_data")
                endex = index + cdata.sdl_nlen
                ll_name = view[index:endex].tobytes().decode()
                assert ll_name == name
                ll_network_addr: HardwareEthernet = view[endex : endex + cdata.sdl_alen].hex(":")
                # print(ll_name, ll_network_addr, interface_index)
                del view, buf

            case _ if element.ifa_addr != ffi.NULL:
                assert False

        match element.ifa_dstaddr:
            case ffi.NULL:
                broadcast_ip = p2p_ip = None
            case _:
                match family:
                    case socket.AF_INET:
                        cdata = ffi.cast("struct sockaddr_in *", element.ifa_dstaddr)
                        with memoryview(buf := ffi.buffer(cdata.sin_addr)) as view:
                            broadcast_ip = ipaddress.ip_address(view.tobytes())
                            assert isinstance(broadcast_ip, ipaddress.IPv4Address)
                    case socket.AF_INET6:
                        cdata = ffi.cast("struct sockaddr_in6 *", element.ifa_dstaddr)
                        with memoryview(buf := ffi.buffer(cdata.sin6_addr)) as view:
                            broadcast_ip = ipaddress.ip_address(view.tobytes())
                            assert isinstance(broadcast_ip, ipaddress.IPv6Address)
                    case _:
                        assert False

        match element.ifa_netmask:
            case ffi.NULL:
                netmask = None
            case _:
                match family:
                    case socket.AF_INET:
                        cdata = ffi.cast("struct sockaddr_in *", element.ifa_netmask)
                        with memoryview(buf := ffi.buffer(cdata.sin_addr)) as view:
                            netmask = ipaddress.ip_address(view.tobytes())
                            assert isinstance(netmask, ipaddress.IPv4Address)
                    case socket.AF_INET6:
                        cdata = ffi.cast("struct sockaddr_in6 *", element.ifa_netmask)
                        with memoryview(buf := ffi.buffer(cdata.sin6_addr)) as view:
                            netmask = ipaddress.ip_address(view.tobytes())
                    case _:
                        assert False
        match element.ifa_data:
            case ffi.NULL:
                pass

            case _:
                match family:
                    case socket.AF_LINK:
                        stat_cdata = ffi.cast("struct if_data*", element.ifa_data)
                        link_statistics = {}
                        for key in dir(stat_cdata):
                            stat_value = getattr(stat_cdata, key)
                            match (key, stat_value):
                                case ("ifi_lastchange", ffi.CData()):
                                    # ARJ: Write into this array of two int64s
                                    # from the ``read_last_change_on``
                                    with allocator.new("int64_t[2]") as buf:
                                        lib.read_last_change_on(
                                            stat_cdata,
                                            ffi.addressof(buf, 0),
                                            ffi.addressof(buf, 1),
                                        )
                                        tv_sec, tv_usec = buf
                                        at = datetime.datetime.fromtimestamp(
                                            tv_sec, datetime.UTC
                                        ) + datetime.timedelta(microseconds=tv_usec)
                                    link_statistics[key] = at
                                case ("ifi_baudrate", int()):
                                    n, rem = divmod(stat_value, 1_000_000)
                                    if n > 0:
                                        link_statistics[key] = Rate(n + (rem / 1_000_000), "Mbps")
                                    else:
                                        n, rem = divmod(stat_value, 1_000)
                                        if n > 0:
                                            link_statistics[key] = Rate(n + (rem / 1_000), "Kbps")
                                        else:
                                            link_statistics[key] = Rate(stat_value, "bps")
                                case (str(), int()):
                                    link_statistics[key] = stat_value
                                case _:
                                    raise NotImplementedError(key)
                    case _:
                        assert False

        match family:
            case socket.AF_INET:
                record = Internet4.new(family, flags, ip, netmask, broadcast_ip)
            case socket.AF_INET6:
                record = Internet6.new(family, flags, ip, netmask, p2p_ip)
            case socket.AF_LINK:
                record = Link.new(
                    family,
                    flags,
                    ll_network_addr,
                    interface_index,
                    if_data_cls(**link_statistics),
                )
            case _:
                assert False
        try:
            rows = interfaces_by_name[name]
        except KeyError:
            rows = interfaces_by_name[name] = [record]
        else:
            rows.append(record)
    for if_name in interfaces_by_name:
        rows = interfaces_by_name[if_name]
        yield NetworkInterface.new(if_name, rows)


class _NetworkInterface(NamedTuple):
    name: str
    rows: tuple[Link | Internet4 | Internet6, ...]
    ipv4_address_indices: tuple[int, ...]
    ipv6_address_indices: tuple[int, ...]
    link_layer_address_indices: tuple[int, ...]

    @property
    def hardware_ethernet(self):
        (index,) = self.link_layer_address_indices
        return self.rows[index].hardware_ethernet

    @property
    def scope_id(self):
        (i,) = self.link_layer_address_indices
        return self.rows[i].index

    @property
    def statistics(self):
        (i,) = self.link_layer_address_indices
        return self.rows[i].statistics

    @property
    def ipv6_addresses(self) -> tuple[Internet6, ...]:
        return tuple(self.rows[index] for index in self.ipv6_address_indices)

    @property
    def ipv4_addresses(self) -> tuple[Internet4, ...]:
        return tuple(self.rows[index] for index in self.ipv4_address_indices)

    @property
    def link_layer_addresses(self) -> tuple[Link, ...]:
        return tuple(self.rows[index] for index in self.link_layer_address_indices)


class NetworkInterface(EnhancedSerialize, _NetworkInterface):
    __slots__ = ()

    @property
    def type(self):
        match self:
            case _ if self.ipv4_address_indices and self.ipv6_address_indices:
                return "dual-stack"
            case _ if self.ipv4_address_indices:
                return "ipv4"
            case _ if self.ipv6_address_indices:
                return "ipv6"
            case _:
                return "linklayer-only"

    @classmethod
    def new(cls, name: str, rows):
        rows = tuple(rows)
        assert rows
        assert all(isinstance(row, (Internet4, Internet6, Link)) for row in rows)
        ipv6_address_indices = []
        ipv4_address_indices = []
        link_layer_address_indices = []
        for index, item in enumerate(rows):
            match item:
                case Internet4():
                    ipv4_address_indices.append(index)
                    assert item.family is socket.AddressFamily.AF_INET
                case Internet6():
                    assert item.family is socket.AddressFamily.AF_INET6
                    ipv6_address_indices.append(index)
                case Link():
                    link_layer_address_indices.append(index)
                case _:
                    assert False

        assert sum(1 for r in rows if isinstance(r, Link)) in (0, 1)
        nic = cls(
            name,
            rows,
            tuple(ipv4_address_indices),
            tuple(ipv6_address_indices),
            tuple(link_layer_address_indices),
        )
        assert any((nic.link_layer_addresses, nic.ipv4_addresses, nic.ipv6_addresses))
        return nic


class _Rate(NamedTuple):
    value: float | int
    unit: str


class Rate(EnhancedSerialize, _Rate):
    __slots__ = ()


class _Link(NamedTuple):
    family: socket.AddressFamily
    flags: InterfaceFlags
    hardware_ethernet: str
    index: int
    statistics: dict[str, int | datetime.datetime]
    ifname: str


class Link(EnhancedSerialize, _Link):
    __slots__ = ()

    @classmethod
    def new(cls, family, flags, hardware_ethernet, index, statistics):
        if index > -1:
            ifname = socket.if_indextoname(index)
        return cls(family, InterfaceFlags(flags), hardware_ethernet, index, statistics, ifname)

    @property
    def mtu(self) -> int:
        return self.statistics.ifi_mtu


class _Internet4(NamedTuple):
    interface: ipaddress.IPv4Interface
    family: socket.AddressFamily
    flags: InterfaceFlags
    ip: ipaddress.IPv4Address
    netmask: ipaddress.IPv4Address
    broadcast: ipaddress.IPv4Address


class _Internet6(NamedTuple):
    interface: ipaddress.IPv6Interface
    family: socket.AddressFamily
    flags: InterfaceFlags
    ip: ipaddress.IPv6Address
    prefix: int
    p2p_ip: ipaddress.IPv6Address


class Internet:
    __slots__ = ()


class Internet4(EnhancedSerialize, Internet, _Internet4):
    __slots__ = ()

    @classmethod
    def new(
        cls,
        family,
        flags: int,
        ip: ipaddress.IPv4Address,
        netmask: ipaddress.IPv4Address,
        broadcast_address: ipaddress.IPv4Address,
    ):
        assert isinstance(ip, ipaddress.IPv4Address)
        assert isinstance(netmask, ipaddress.IPv4Address)
        interface = ipaddress.IPv4Interface((ip, f"{netmask!s}"))
        assert family is socket.AddressFamily.AF_INET

        return cls(interface, family, InterfaceFlags(flags), ip, netmask, broadcast_address)


class Internet6(EnhancedSerialize, Internet, _Internet6):
    __slots__ = ()

    @classmethod
    def new(
        cls,
        family,
        flags: int,
        ip: ipaddress.IPv6Address,
        netmask: ipaddress.IPv6Address,
        p2p_ip: ipaddress.IPv6Address,
    ):
        prefix = bin(int(netmask)).count("1")
        interface = ipaddress.IPv6Interface((ip, prefix))
        assert isinstance(ip, ipaddress.IPv6Address)
        assert family is socket.AddressFamily.AF_INET6
        return cls(interface, family, InterfaceFlags(flags), ip, prefix, p2p_ip)


def _warn_or_log(*args, **kwargs):
    logger.warning(*args, **kwargs)
    root = logging.getLogger("")
    if not any(handler for a_logger in (logger, root) for handler in a_logger.handlers):
        print("warning", args[0], file=sys.stderr, flush=True)


if __name__ == "__main__":
    import logging
    import pprint
    import textwrap

    logging.basicConfig()
    logger.setLevel(logging.DEBUG)
    c = 0
    for interface in list_interfaces():
        if not any((interface.ipv4_addresses, interface.ipv6_addresses)):
            continue
        c += 1
        v = pprint.pformat(
            interface._asdict(options=Serialization.INCLUDES_PROPERTIES | Serialization.NO_RECURSE)
        )
        print(f"  {c}.\t{textwrap.indent(v, 12 *' ').lstrip()}")
