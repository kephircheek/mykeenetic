import unittest
from dataclasses import asdict

from mykeenetic import HostRoute, NetworkRoute, as_route


class TestRouteObject(unittest.TestCase):
    def setUp(self):
        self.hroute = HostRoute(interface="Proxy1", comment="test host", host="111.111.111.111")
        self.nroute = NetworkRoute(
            interface="Proxy1",
            comment="test network",
            network="111.111.111.0",
            mask="255.255.255.0",
        )

    def test_hashing(self):
        routes = set([self.hroute] * 2 + [self.nroute] * 2)
        self.assertEqual(len(routes), 2)

    def test_as_route_for_host_route(self):
        self.assertEqual(as_route(asdict(self.hroute)), self.hroute)

    def test_as_route_for_network_route(self):
        self.assertEqual(as_route(asdict(self.nroute)), self.nroute)
