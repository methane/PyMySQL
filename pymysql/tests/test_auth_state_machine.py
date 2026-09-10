"""Unit tests for authentication packet transitions."""

from unittest import mock

import pytest

import pymysql
from pymysql import _auth
from pymysql.constants import CLIENT
from pymysql.protocol import MysqlPacket


class TestAuthenticationStateMachine:
    password = b"router-password"
    salt = b"01234567890123456789"
    ok_packet = b"\0\0\0\2\0\0\0"

    @staticmethod
    def packet(data):
        return MysqlPacket(data, "utf8")

    @pytest.mark.parametrize(
        ("responses", "expected_auth_responses"),
        [
            ([b"\x01\x04", ok_packet], [password + b"\0"]),
            (
                [b"\xfemysql_native_password\0" + salt + b"\0", ok_packet],
                [_auth.scramble_native_password(password, salt)],
            ),
            (
                [
                    b"\x01\x04",
                    b"\xfemysql_native_password\0" + salt + b"\0",
                    ok_packet,
                ],
                [password + b"\0", _auth.scramble_native_password(password, salt)],
            ),
        ],
        ids=["more-data", "auth-switch", "more-data-then-auth-switch"],
    )
    def test_authentication_packet_transitions(
        self, responses, expected_auth_responses
    ):
        """Exercise multi-step authentication without a MySQL server or Router."""
        conn = pymysql.connect(
            user="router-user",
            password=self.password,
            ssl_disabled=True,
            defer_connect=True,
        )
        conn.server_version = "8.0.0"
        conn.server_capabilities = CLIENT.PLUGIN_AUTH | CLIENT.SECURE_CONNECTION
        conn.client_flag = CLIENT.PLUGIN_AUTH | CLIENT.SECURE_CONNECTION
        conn.salt = self.salt
        conn._auth_plugin_name = "caching_sha2_password"
        conn._secure = True

        packets = [self.packet(response) for response in responses]
        with (
            mock.patch.object(conn, "write_packet") as write_packet,
            mock.patch.object(conn, "_read_packet", side_effect=packets),
        ):
            conn._request_authentication()

        # The first write is the handshake response; subsequent writes are the
        # authentication state-machine responses asserted by each scenario.
        assert [call.args[0] for call in write_packet.call_args_list[1:]] == (
            expected_auth_responses
        )

    def test_multiple_auth_switch_requests_are_rejected(self):
        """Only one authentication-method switch is valid per handshake."""
        conn = pymysql.connect(
            user="router-user",
            password=self.password,
            ssl_disabled=True,
            defer_connect=True,
        )
        conn.server_version = "8.0.0"
        conn.server_capabilities = CLIENT.PLUGIN_AUTH | CLIENT.SECURE_CONNECTION
        conn.client_flag = CLIENT.PLUGIN_AUTH | CLIENT.SECURE_CONNECTION
        conn.salt = self.salt
        conn._auth_plugin_name = "caching_sha2_password"
        conn._secure = True

        packets = [
            self.packet(b"\xfemysql_native_password\0" + self.salt + b"\0"),
            self.packet(b"\xfesha256_password\0" + self.salt + b"\0"),
        ]
        with (
            mock.patch.object(conn, "write_packet"),
            mock.patch.object(conn, "_read_packet", side_effect=packets),
            pytest.raises(
                pymysql.err.OperationalError,
                match="received multiple auth switch requests",
            ),
        ):
            conn._request_authentication()
