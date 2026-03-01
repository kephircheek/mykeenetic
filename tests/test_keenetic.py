"""
Environment variables:
- KEENETIC_USERNAME
- KEENETIC_PASSWORD
- KEENETIC_ENDPOINT
"""

import os
import unittest
from getpass import getpass

from keenetic import Keenetic, HostRoute, Status


def setUpModule():
    endpoint = os.getenv("KEENETIC_ENDPOINT")
    username = os.getenv("KEENETIC_USERNAME")
    password = os.getenv("KEENETIC_PASSWORD")
    if password is None:
        password = getpass(f"Username: {username}\nPassword:")
    global KEENETIC
    KEENETIC = Keenetic(password=password, login=username, endpoint=endpoint).auth()


class TestRouteIP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.new_routes = [
            HostRoute(**{"interface": "Proxy0", "comment": "test", "host": "111.111.111.111"}),
            HostRoute(**{"interface": "Proxy0", "comment": "test", "host": "222.222.222.222"}),
        ]

    def test_ip_route(self):
        routes = KEENETIC.ip_route()
        self.assertNotEqual(len(routes), 0)

    def test_ip_route_del_non_existent(self):
        self.assertListEqual(KEENETIC.ip_route_del(self.new_routes), [Status.NO_SUCH_ROUTE] * 2)

    def test_ip_route_add_and_del(self):
        self.assertListEqual(
            KEENETIC.ip_route_add(self.new_routes), [Status.ADDED_STATIC_ROUTE] * 2
        )
        self.assertListEqual(
            KEENETIC.ip_route_add(self.new_routes), [Status.RENEWED_STATIC_ROUTE] * 2
        )

        self.assertListEqual(
            KEENETIC.ip_route_del(self.new_routes), [Status.DELETED_STATIC_ROUTE] * 2
        )
