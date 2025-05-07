"""
Environment variables:
- KEENETIC_USERNAME
- KEENETIC_PASSWORD
- KEENETIC_ENDPOINT
"""
import os
import unittest
from getpass import getpass

from keenetic import *


def setUpModule():
    global ENDPOINT
    global OPENER
    username = os.getenv("KEENETIC_USERNAME", "admin")
    password = os.getenv("KEENETIC_PASSWORD")
    if password is None:
        password = getpass(f"Username: {username}\nPassword:")
    ENDPOINT = os.getenv("KEENETIC_ENDPOINT", "my.keenetic.net")
    OPENER = auth(ENDPOINT, username, password)
    if OPENER is None:
        raise RuntimeError(f"can not authorize on '{ENDPOINT}' with '{OPENER}'")


class TestRouteIP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.new_routes = [
            HostRoute(**{"interface": "Proxy0", "comment": "test", "host": "111.111.111.111"}),
            HostRoute(**{"interface": "Proxy0", "comment": "test", "host": "222.222.222.222"}),
        ]

    def test_ip_route(self):
        routes = ip_route(OPENER, ENDPOINT)
        self.assertNotEqual(len(routes), 0)

    def test_ip_route_del_non_existent(self):
        self.assertListEqual(
            ip_route_del(OPENER, ENDPOINT, self.new_routes), [Status.NO_SUCH_ROUTE] * 2
        )

    def test_ip_route_add_and_del(self):
        self.assertListEqual(
            ip_route_add(OPENER, ENDPOINT, self.new_routes), [Status.ADDED_STATIC_ROUTE] * 2
        )
        self.assertListEqual(
            ip_route_add(OPENER, ENDPOINT, self.new_routes), [Status.RENEWED_STATIC_ROUTE] * 2
        )

        self.assertListEqual(
            ip_route_del(OPENER, ENDPOINT, self.new_routes), [Status.DELETED_STATIC_ROUTE] * 2
        )
