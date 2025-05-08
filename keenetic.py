import hashlib
import http.client
import http.cookiejar
import ipaddress
import itertools
import json
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from enum import Enum


class Status(Enum):
    ADDED_STATIC_ROUTE = 5046275
    RENEWED_STATIC_ROUTE = 8912996
    DELETED_STATIC_ROUTE = 5046278
    NO_SUCH_ROUTE = 5046328
    NO_SUCH_INTERFACE = 5046299
    NOT_FOUND = 1179781


def auth_hash(login, passwd, token, realm):
    md5_hash = hashlib.md5(f"{login}:{realm}:{passwd}".encode()).hexdigest()
    sha256_hash = hashlib.sha256(f"{token}{md5_hash}".encode()).hexdigest()
    return sha256_hash


def auth(endpoint, login, passwd, retry=None):
    cookie_jar = http.cookiejar.CookieJar()
    cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
    opener = urllib.request.build_opener(cookie_handler)

    url = f"http://{endpoint}/auth"
    auth_check_req = urllib.request.Request(url)
    try:
        response = opener.open(auth_check_req)
        return opener
    except urllib.error.HTTPError as err:
        if err.code == 401:
            token = err.headers.get("X-NDM-Challenge")
            realm = err.headers.get("X-NDM-Realm")
            auth_hash_ = auth_hash(login, passwd, token, realm)
            data = {"login": login, "password": auth_hash_}
            data = json.dumps(data).encode("utf-8")

            auth_req = urllib.request.Request(url, data=data, method="POST")
            auth_req.add_header("Content-Type", "application/json")
            try:
                auth_response = opener.open(auth_req)
                if auth_response.getcode() == 200:
                    return opener
                return None
            except urllib.error.HTTPError as err:
                if err.code == 401:
                    return None
                raise err
        raise err
    return None


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


def ip_route(opener, endpoint) -> tuple[HostRoute | NetworkRoute, ...]:
    url = f"http://{endpoint}/rci/ip/route/"
    req = urllib.request.Request(url)
    response = opener.open(req)
    data = response.read().decode("utf-8")
    routes = json.loads(data)
    routes = tuple(HostRoute(**r) if "host" in r else NetworkRoute(**r) for r in routes)
    return routes


def _ip_route_batched_update(
    opener, endpoint, routes: list[HostRoute | NetworkRoute], delete=False
):
    batch_size = 1024
    routes_batches = (routes[i : i + batch_size] for i in range(0, len(routes), batch_size))
    return list(
        itertools.chain.from_iterable(
            _ip_route_update(opener, endpoint, routes_batch, delete=delete)
            for routes_batch in routes_batches
        )
    )


def _ip_route_update(opener, endpoint, routes: list[HostRoute | NetworkRoute], delete=False):
    url = f"http://{endpoint}/rci/"
    no = {"no": True} if delete else {}
    data = [{"ip": {"route": asdict(route) | no}} for route in routes]
    data.append({"system": {"configuration": {"save": True}}})
    data = json.dumps(data).encode("utf-8")
    rci_req = urllib.request.Request(url, data=data, method="POST")
    rci_req.add_header("Content-Type", "application/json")
    rci_response = opener.open(rci_req)
    if rci_response.getcode() == 200:
        response_data = json.loads(rci_response.read().decode("utf-8"))
        statuses = []
        for data in response_data:
            if "system" in data:
                continue
            routes = data["ip"]["route"]
            routes = routes if isinstance(routes, list) else [routes]
            for route in routes:
                for status in route["status"]:
                    status_key = status["message"].split(":", 1)[0].replace(" ", "_").upper()
                    try:
                        statuses.append(Status[status_key])
                    except KeyError as err:
                        print(json.dumps(data))
                        statuses.append(str(err))
        return statuses


def ip_route_add(opener, endpoint, routes: list[HostRoute | NetworkRoute]):
    return _ip_route_batched_update(opener, endpoint, routes)


def ip_route_del(opener, endpoint, routes: list[HostRoute | NetworkRoute]):
    return _ip_route_batched_update(opener, endpoint, routes, delete=True)


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
        cidr2route(cidr=ip_range, interface=interface, comment=comment) for ip_range in ranges
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


def show_system(endpoint, opener):
    """
    Examples
    --------
    {
      "hostname": "Keenetic-0630",
      "domainname": "WORKGROUP",
      "cpuload": 2,
      "memory": "100532/524288",
      "swap": "0/524284",
      "memtotal": 524288,
      "memfree": 366448,
      "membuffers": 12276,
      "memcache": 45032,
      "swaptotal": 524284,
      "swapfree": 524284,
      "uptime": "36296",
      "conntotal": 32768,
      "connfree": 32563
    }
    """
    url = f"http://{endpoint}/rci/show/system"
    raise NotImplementetError
