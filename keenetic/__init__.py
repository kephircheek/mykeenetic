import hashlib
import http.client
import http.cookiejar
import ipaddress
import itertools
import json
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, replace
from enum import Enum


class Status(Enum):
    ADDED_STATIC_ROUTE = 5046275
    RENEWED_STATIC_ROUTE = 8912996
    DELETED_STATIC_ROUTE = 5046278
    NO_SUCH_ROUTE = 5046328
    NO_SUCH_INTERFACE = 5046299
    NOT_FOUND = 1179781

    @classmethod
    def from_json(cls, status):
        status_key = status["message"].split(":", 1)[0].replace(" ", "_").upper()
        try:
            return cls[status_key]
        except KeyError:
            print(json.dumps(data))
            return {status_key: status["code"]}


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


@dataclass(frozen=True)
class Keenetic:
    password: str
    login: str | None = None
    endpoint: str | None = None
    opener: urllib.request.OpenerDirector = None
    secure: bool = False

    @property
    def endpoint_(self):
        return self.endpoint or "my.keenetic.net"

    @property
    def login_(self):
        return self.login or "admin"

    @property
    def base_url(self):
        scheme = "https" if self.secure else "http"
        return f"{scheme}://{self.endpoint_}"

    def auth_hash(self, token, realm):
        md5_hash = hashlib.md5(f"{self.login_}:{realm}:{self.password}".encode()).hexdigest()
        sha256_hash = hashlib.sha256(f"{token}{md5_hash}".encode()).hexdigest()
        return sha256_hash

    def auth(self):
        cookie_jar = http.cookiejar.CookieJar()
        cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
        opener = urllib.request.build_opener(cookie_handler)
        auth_url = f"{self.base_url}/auth"
        auth_check_req = urllib.request.Request(auth_url)
        try:
            response = opener.open(auth_check_req)
            return self
        except urllib.error.HTTPError as err:
            if err.code == 401:
                token = err.headers.get("X-NDM-Challenge")
                realm = err.headers.get("X-NDM-Realm")
                auth_hash_ = self.auth_hash(token, realm)
                data = {"login": self.login_, "password": auth_hash_}
                data = json.dumps(data).encode("utf-8")
                auth_req = urllib.request.Request(auth_url, data=data, method="POST")
                auth_req.add_header("Content-Type", "application/json")
                auth_response = opener.open(auth_req)
                return replace(self, opener=opener)
            raise err

    def run(self, cmd: str = None, data=None):
        url = f"{self.base_url}/rci/"
        if cmd is not None:
            url += cmd.strip().replace(" ", "/")
        if data is None:
            req = urllib.request.Request(url)
        else:
            data = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
        response = self.opener.open(req)
        if response.getcode() != 200:
            raise RuntimeError(f"response has code: {response.getcode()} != 200")
        return json.loads(response.read().decode("utf-8"))

    def ip_route(self) -> tuple[HostRoute | NetworkRoute, ...]:
        routes = self.run("ip route")
        routes = tuple(HostRoute(**r) if "host" in r else NetworkRoute(**r) for r in routes)
        return routes

    def _ip_route_update(self, routes: list[HostRoute | NetworkRoute], delete=False):
        no = {"no": True} if delete else {}
        data = [{"ip": {"route": asdict(route) | no}} for route in routes]
        data.append({"system": {"configuration": {"save": True}}})
        response_data = self.run(data=data)
        statuses = []
        for data_amount in response_data:
            if "system" in data_amount:
                continue
            routes = data_amount["ip"]["route"]
            routes = routes if isinstance(routes, list) else [routes]
            for route in routes:
                for status in route["status"]:
                    statuses.append(Status.from_json(status))
        return statuses

    def _ip_route_batched_update(self, routes: list[HostRoute | NetworkRoute], delete=False):
        batch_size = 1024
        routes_batches = (routes[i : i + batch_size] for i in range(0, len(routes), batch_size))
        return list(
            itertools.chain.from_iterable(
                self._ip_route_update(routes_batch, delete=delete)
                for routes_batch in routes_batches
            )
        )

    def ip_route_add(self, routes: list[HostRoute | NetworkRoute]):
        return self._ip_route_batched_update(routes)

    def ip_route_del(self, routes: list[HostRoute | NetworkRoute]):
        return self._ip_route_batched_update(routes, delete=True)

    def show_log(self, idents: set = None, max_lines=None):
        payload = None
        if max_lines is not None:
            payload = {"max-lines": max_lines}
        response = self.run("show log", payload)
        if "log" not in response:
            return []
        messages = response["log"].values()
        return [msg for msg in messages if not idents or msg["ident"] in idents]

    def search_interface_id(self, decription, id_prefix):
        return (
            i for i in self.run("show interface").values()
            if i.get("description", "") == decription and i["id"].startswith(id_prefix)
        )
