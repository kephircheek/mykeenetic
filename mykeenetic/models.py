import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class _Route:
    interface: str
    comment: str


@dataclass(frozen=True)
class HostRoute(_Route):
    host: str

    @property
    def address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(self.host)


@dataclass(frozen=True)
class NetworkRoute(_Route):
    network: str
    mask: str

    @property
    def address(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(f"{self.network}/{self.mask}")


def as_route(obj):
    if "network" in obj:
        return NetworkRoute(**obj)
    if "host" in obj:
        return HostRoute(**obj)
    raise ValueError(f"not match to route object: {obj}")


def cidr_to_ip_and_mask(cidr: str) -> (str, str):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.version != 4:
            # print(f"Unsupported IP version: {network.version} != 4")
            return None, None
    except ipaddress.AddressValueError as e:
        print(f"{cidr} -> Error: {e}. This CIDR notation is not valid.")
        return None, None
    except ipaddress.NetmaskValueError as e:
        print(f"{cidr} -> Error: {e}. This CIDR notation is not valid.")
        return None, None
    except Exception as e:
        print(f"{cidr} -> An unexpected error occurred: {e}")
        return None, None

    return str(network.network_address), str(network.netmask)


def ranges2routes(ranges: list[str], interface, comment: str):
    routes = [
        cidr2route(cidr=ip_range, interface=interface, comment=comment)
        for ip_range in ranges
    ]
    return [r for r in routes if r is not None]


def cidr2route(cidr, interface, comment):
    ip, mask = cidr_to_ip_and_mask(cidr)
    if ip is None:
        return None
    if mask is not None:
        return NetworkRoute(
            interface=interface,
            comment=comment,
            network=ip,
            mask=mask,
        )
    return HostRoute(
        interface=interface,
        comment=comment,
        host=ip,
    )
