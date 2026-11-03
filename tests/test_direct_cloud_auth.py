"""Direct Cloud auth: GeekSmart login first, then Tuya login with the
GeekSmart-provisioned bridge account (tuyaUsername / tuyaPassword).

Regression for HA config flow failing with
``Tuya API Error [USER_PASSWD_WRONG]`` when the user's GeekSmart password was
sent straight to Tuya. All credentials below are fake test fixtures.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from typing import Any, Dict, List
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa

from custom_components.geek_door.core.exceptions import GeekSmartAuthError, TuyaApiError
from custom_components.geek_door.core.geeksmart_client import GeekSmartClient
from custom_components.geek_door.core.lock_engine import LockEngine
from custom_components.geek_door.core.tuya_client import TuyaClient

APP_EMAIL = "user@example.com"
APP_PASSWORD = "app-password-123"          # what the user types in HA
BRIDGE_USERNAME = "user@example.com"        # GeekSmart-linked Tuya account
BRIDGE_PASSWORD = "a1b2c3d4"                # random value GeekSmart provisions
BRIDGE_COUNTRY = 1


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


class FakeTuyaCloud:
    """Minimal Tuya mobile API: token.get + email.password.login with real RSA."""

    def __init__(self, username: str, password: str, country: str = "1") -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.username = username
        self.password_md5 = _md5(password)
        self.country = country
        self.login_calls: List[Dict[str, Any]] = []

    def request(self, action: str, version: str, post_data=None, requires_session=False, **_kw):
        post_data = post_data or {}
        if action == "thing.m.user.username.token.get":
            pub = self._key.public_key().public_numbers()
            return {"token": "tok", "publicKey": str(pub.n), "exponent": str(pub.e)}
        if action == "thing.m.user.email.password.login":
            self.login_calls.append(dict(post_data))
            sent_md5 = self._key.decrypt(
                bytes.fromhex(post_data["passwd"]), asym_padding.PKCS1v15()
            ).decode()
            if (
                post_data["email"] != self.username
                or sent_md5 != self.password_md5
                or str(post_data["countryCode"]) != self.country
            ):
                raise TuyaApiError("USER_PASSWD_WRONG", "Incorrect account or password")
            return {"sid": "sid-ok", "ecode": "ec", "uid": "tuya-uid", "expiresIn": 3600}
        raise AssertionError(f"unexpected action {action}")


def _geeksmart_transport(bean: Dict[str, Any], calls: List[Dict[str, Any]]):
    def transport(endpoint: str, params: Dict[str, Any], method: str) -> Dict[str, Any]:
        calls.append({"endpoint": endpoint, "params": dict(params)})
        if "loginByPassword" in endpoint:
            if params.get("email") == APP_EMAIL and params.get("password") == APP_PASSWORD:
                return {"code": 0, "msg": "ok", "data": bean}
            return {"code": 2007, "msg": "Incorrect account or password", "data": None}
        return {"code": 0, "msg": "ok", "data": None}
    return transport


def _bean(**overrides: Any) -> Dict[str, Any]:
    bean = {
        "id": 42,
        "email": APP_EMAIL,
        "token": "gs-token",
        "password": _md5(APP_PASSWORD),
        "tuyaUid": "tuya-uid",
        "tuyaUsername": BRIDGE_USERNAME,
        "tuyaPassword": BRIDGE_PASSWORD,
        "tuyaPasswordMd5": _md5(BRIDGE_PASSWORD),
        "tuyaCountryCode": BRIDGE_COUNTRY,
        "tuyaUsernameType": 2,
    }
    bean.update(overrides)
    return {k: v for k, v in bean.items() if v is not None}


class TestDirectCloudAuth(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = os.path.join(self.tmp.name, ".session_cache.json")
        self.gs_calls: List[Dict[str, Any]] = []

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _engine(self, bean: Dict[str, Any], cloud: FakeTuyaCloud) -> LockEngine:
        gs = GeekSmartClient(
            session_cache_path=self.cache,
            mock_transport=_geeksmart_transport(bean, self.gs_calls),
        )
        tc = TuyaClient(session_cache_path=self.cache, load_cache=False)
        tc.request = cloud.request  # type: ignore[assignment]
        engine = LockEngine(
            session_cache_path=self.cache,
            gs_client=gs,
            tuya_client=tc,
            sample_mode=False,
            use_sample_devices=False,
        )
        return engine

    def _run(self, engine: LockEngine, password: str = APP_PASSWORD, country: str = "1"):
        with patch.object(LockEngine, "discover", return_value={"locks": [{"devId": "lock_1"}]}):
            return engine.authenticate_and_discover(APP_EMAIL, password, country)

    def test_uses_geeksmart_provisioned_tuya_credentials(self) -> None:
        cloud = FakeTuyaCloud(BRIDGE_USERNAME, BRIDGE_PASSWORD)
        engine = self._engine(_bean(), cloud)
        devices = self._run(engine)
        self.assertEqual(devices, [{"devId": "lock_1"}])
        self.assertTrue(any("loginByPassword" in c["endpoint"] for c in self.gs_calls))
        self.assertEqual(len(cloud.login_calls), 1)
        self.assertEqual(engine.tuya_client.sid, "sid-ok")

    def test_user_password_alone_is_rejected_by_tuya(self) -> None:
        """Documents the root cause: Tuya rejects the GeekSmart app password."""
        cloud = FakeTuyaCloud(BRIDGE_USERNAME, BRIDGE_PASSWORD)
        tc = TuyaClient(session_cache_path=self.cache, load_cache=False)
        tc.request = cloud.request  # type: ignore[assignment]
        with self.assertRaises(TuyaApiError) as ctx:
            tc.login(APP_EMAIL, APP_PASSWORD, "1", use_cache=False)
        self.assertIn("USER_PASSWD_WRONG", str(ctx.exception))

    def test_md5_only_bridge_password(self) -> None:
        cloud = FakeTuyaCloud(BRIDGE_USERNAME, BRIDGE_PASSWORD)
        engine = self._engine(_bean(tuyaPassword=None), cloud)
        self._run(engine)
        self.assertEqual(engine.tuya_client.sid, "sid-ok")

    def test_bridge_username_and_country_from_geeksmart(self) -> None:
        cloud = FakeTuyaCloud("geek_sub_42@tuya.example", BRIDGE_PASSWORD, country="86")
        engine = self._engine(_bean(tuyaUsername="geek_sub_42@tuya.example", tuyaCountryCode=86), cloud)
        self._run(engine, country="1")
        self.assertEqual(cloud.login_calls[0]["email"], "geek_sub_42@tuya.example")
        self.assertEqual(str(cloud.login_calls[0]["countryCode"]), "86")

    def test_wrong_geeksmart_password_fails_before_tuya(self) -> None:
        cloud = FakeTuyaCloud(BRIDGE_USERNAME, BRIDGE_PASSWORD)
        engine = self._engine(_bean(), cloud)
        with self.assertRaises(GeekSmartAuthError):
            self._run(engine, password="wrong")
        self.assertEqual(cloud.login_calls, [])

    def test_fallback_to_raw_tuya_login_without_bridge_credentials(self) -> None:
        cloud = FakeTuyaCloud(APP_EMAIL, APP_PASSWORD)
        engine = self._engine(_bean(tuyaPassword=None, tuyaPasswordMd5=None), cloud)
        self._run(engine)
        self.assertEqual(engine.tuya_client.sid, "sid-ok")


if __name__ == "__main__":
    unittest.main()
