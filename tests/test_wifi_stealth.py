# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""Tests for WiFi Stealth system — network SSID hiding and scanning."""

import asyncio
import urllib.error
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from network_guardian.config import Config
from network_guardian.core.engine import Engine
from network_guardian.core.events import EventBus
from network_guardian.cloaking import (
    GatewayDetector,
    RouterAdmin,
    RouterConfig,
    SSIDState,
    WiFiNetwork,
    WiFiScanner,
    WiFiStealthSystem,
)


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

@pytest.fixture
def config():
    return Config()


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def stealth(config, bus):
    return WiFiStealthSystem(config, bus)


@pytest.fixture
def scanner():
    return WiFiScanner()


@pytest.fixture
def gateway_detector():
    return GatewayDetector()


@pytest.fixture
def router_admin():
    return RouterAdmin()


# -----------------------------------------------------------------------
# WiFiNetwork dataclass
# -----------------------------------------------------------------------

class TestWiFiNetwork:
    def test_basic_network(self):
        net = WiFiNetwork(ssid="HomeNet", bssid="AA:BB:CC:DD:EE:FF", signal=75)
        assert net.ssid == "HomeNet"
        assert net.bssid == "AA:BB:CC:DD:EE:FF"
        assert net.signal == 75
        assert not net.hidden

    def test_hidden_network(self):
        net = WiFiNetwork(ssid="", hidden=True)
        assert net.hidden
        assert net.as_dict["ssid"] == "(hidden)"

    def test_as_dict(self):
        net = WiFiNetwork(
            ssid="Test", bssid="11:22:33:44:55:66", signal=80,
            channel=6, security="WPA2", frequency="2.4 GHz",
        )
        d = net.as_dict
        assert d["ssid"] == "Test"
        assert d["channel"] == 6
        assert d["security"] == "WPA2"
        assert d["frequency"] == "2.4 GHz"
        assert d["hidden"] is False

    def test_defaults(self):
        net = WiFiNetwork(ssid="X")
        assert net.channel == 0
        assert net.security == "Unknown"
        assert net.frequency == ""


# -----------------------------------------------------------------------
# RouterConfig
# -----------------------------------------------------------------------

class TestRouterConfig:
    def test_set_credentials(self):
        cfg = RouterConfig(ip="192.168.1.1")
        cfg.set_credentials("admin", "secret123")
        assert cfg.username == "admin"
        assert cfg.auth_header.startswith("Basic ")

    def test_as_dict_unconfigured(self):
        cfg = RouterConfig(ip="10.0.0.1")
        d = cfg.as_dict
        assert d["ip"] == "10.0.0.1"
        assert d["configured"] is False

    def test_as_dict_configured(self):
        cfg = RouterConfig(ip="192.168.0.1")
        cfg.set_credentials("root", "pass")
        d = cfg.as_dict
        assert d["configured"] is True
        assert d["username"] == "root"

    def test_default_router_type(self):
        cfg = RouterConfig(ip="192.168.1.1")
        assert cfg.router_type == "auto"


# -----------------------------------------------------------------------
# SSIDState enum
# -----------------------------------------------------------------------

class TestSSIDState:
    def test_values(self):
        assert SSIDState.VISIBLE.value == "visible"
        assert SSIDState.HIDDEN.value == "hidden"
        assert SSIDState.UNKNOWN.value == "unknown"


# -----------------------------------------------------------------------
# WiFiScanner parsing
# -----------------------------------------------------------------------

class TestWiFiScannerParsing:
    def test_parse_netsh_output(self, scanner):
        output = (
            "SSID 1 : HomeNetwork\n"
            "    Network type            : Infrastructure\n"
            "    Authentication          : WPA2-Personal\n"
            "    Encryption              : CCMP\n"
            "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
            "         Signal             : 95%\n"
            "         Radio type         : 802.11ac\n"
            "         Channel            : 36\n"
            "\n"
            "SSID 2 : Neighbor_5G\n"
            "    Network type            : Infrastructure\n"
            "    Authentication          : WPA3-Personal\n"
            "    BSSID 1                 : 11:22:33:44:55:66\n"
            "         Signal             : 42%\n"
            "         Radio type         : 802.11ax\n"
            "         Channel            : 149\n"
        )
        networks = scanner._parse_netsh_output(output)
        assert len(networks) == 2
        assert networks[0].ssid == "HomeNetwork"
        assert networks[0].signal == 95
        assert networks[0].channel == 36
        assert networks[0].security == "WPA2-Personal"
        assert networks[1].ssid == "Neighbor_5G"
        assert networks[1].signal == 42

    def test_parse_netsh_hidden_network(self, scanner):
        output = (
            "SSID 1 : \n"
            "    Network type            : Infrastructure\n"
            "    Authentication          : WPA2-Personal\n"
            "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
            "         Signal             : 50%\n"
            "         Channel            : 1\n"
        )
        networks = scanner._parse_netsh_output(output)
        assert len(networks) == 1
        assert networks[0].hidden is True
        assert networks[0].ssid == ""

    def test_parse_nmcli_output(self, scanner):
        output = (
            "MyWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:FF:85:2412 MHz:WPA2\n"
            "Other:11\\:22\\:33\\:44\\:55\\:66:30:5180 MHz:WPA3\n"
        )
        networks = scanner._parse_nmcli_output(output)
        assert len(networks) == 2
        assert networks[0].ssid == "MyWiFi"
        assert networks[0].signal == 85
        assert networks[0].bssid == "AA:BB:CC:DD:EE:FF"
        assert networks[0].security == "WPA2"
        assert networks[1].ssid == "Other"

    def test_parse_nmcli_hidden(self, scanner):
        output = "--:AA\\:BB\\:CC\\:DD\\:EE\\:FF:60:2437 MHz:WPA2\n"
        networks = scanner._parse_nmcli_output(output)
        assert len(networks) == 1
        assert networks[0].hidden is True

    def test_parse_iwlist_output(self, scanner):
        output = (
            "      Cell 01 - Address: AA:BB:CC:DD:EE:FF\n"
            "                ESSID:\"TestNet\"\n"
            "                Channel:11\n"
            "                Signal level=-45 dBm\n"
            "                Encryption key:on\n"
            "      Cell 02 - Address: 11:22:33:44:55:66\n"
            "                ESSID:\"OpenNet\"\n"
            "                Channel:6\n"
            "                Signal level=-70 dBm\n"
            "                Encryption key:off\n"
        )
        networks = scanner._parse_iwlist_output(output)
        assert len(networks) == 2
        assert networks[0].ssid == "TestNet"
        assert networks[0].channel == 11
        assert networks[0].signal == -45
        assert networks[0].security == "Encrypted"
        assert networks[1].ssid == "OpenNet"
        assert networks[1].security == "Open"

    def test_parse_airport_output(self, scanner):
        output = (
            "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
            "                        HomeNet aa:bb:cc:dd:ee:ff  -50       6  Y  -- WPA2\n"
        )
        networks = scanner._parse_airport_output(output)
        assert len(networks) == 1
        assert networks[0].ssid == "HomeNet"
        assert networks[0].signal == -50
        assert networks[0].channel == 6

    def test_parse_empty_outputs(self, scanner):
        assert scanner._parse_netsh_output("") == []
        assert scanner._parse_nmcli_output("") == []
        assert scanner._parse_iwlist_output("") == []
        assert scanner._parse_airport_output("") == []


# -----------------------------------------------------------------------
# WiFiScanner async methods (mocked OS calls)
# -----------------------------------------------------------------------

class TestWiFiScannerAsync:
    def test_scan_networks_windows(self, scanner):
        scanner._os = "windows"
        fake_output = (
            "SSID 1 : TestWiFi\n"
            "    Authentication          : WPA2-Personal\n"
            "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
            "         Signal             : 80%\n"
            "         Channel            : 6\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            networks = scanner._scan_sync()
            assert len(networks) == 1
            assert networks[0].ssid == "TestWiFi"

    def test_scan_networks_linux_nmcli(self, scanner):
        scanner._os = "linux"
        fake_output = "LinuxNet:AA\\:BB\\:CC:90:2412:WPA2\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            networks = scanner._scan_sync()
            assert len(networks) == 1
            assert networks[0].ssid == "LinuxNet"

    def test_scan_failure_returns_empty(self, scanner):
        scanner._os = "windows"
        with patch("subprocess.run", side_effect=FileNotFoundError):
            networks = scanner._scan_sync()
            assert networks == []

    def test_connected_windows(self, scanner):
        scanner._os = "windows"
        fake_output = (
            "    SSID                   : MyHome\n"
            "    BSSID                  : aa:bb:cc:dd:ee:ff\n"
            "    Signal                 : 92%\n"
            "    Channel                : 11\n"
            "    Authentication         : WPA2-Personal\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            net = scanner._connected_sync()
            assert net is not None
            assert net.ssid == "MyHome"
            assert net.signal == 92

    def test_connected_linux(self, scanner):
        scanner._os = "linux"
        fake_output = "yes:MyNet:AA\\:BB\\:CC:75:2412:WPA2\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            net = scanner._connected_sync()
            assert net is not None
            assert net.ssid == "MyNet"

    def test_connected_not_found(self, scanner):
        scanner._os = "windows"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="No wireless interface")
            net = scanner._connected_sync()
            assert net is None

    def test_unsupported_os_returns_none(self, scanner):
        scanner._os = "freebsd"
        assert scanner._scan_sync() == []
        assert scanner._connected_sync() is None


# -----------------------------------------------------------------------
# GatewayDetector
# -----------------------------------------------------------------------

class TestGatewayDetector:
    def test_detect_windows(self, gateway_detector):
        gateway_detector._os = "windows"
        fake_output = (
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            gw = gateway_detector._detect_sync()
            assert gw == "192.168.1.1"

    def test_detect_linux(self, gateway_detector):
        gateway_detector._os = "linux"
        fake_output = "default via 10.0.0.1 dev eth0 proto dhcp\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            gw = gateway_detector._detect_sync()
            assert gw == "10.0.0.1"

    def test_detect_macos(self, gateway_detector):
        gateway_detector._os = "darwin"
        fake_output = "   route to: default\n   gateway: 192.168.0.1\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=fake_output)
            gw = gateway_detector._detect_sync()
            assert gw == "192.168.0.1"

    def test_detect_failure(self, gateway_detector):
        gateway_detector._os = "windows"
        with patch("subprocess.run", side_effect=FileNotFoundError):
            gw = gateway_detector._detect_sync()
            assert gw is None

    def test_unsupported_os(self, gateway_detector):
        gateway_detector._os = "freebsd"
        assert gateway_detector._detect_sync() is None

    def test_no_gateway_in_output(self, gateway_detector):
        gateway_detector._os = "windows"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Some other text\n")
            gw = gateway_detector._detect_sync()
            assert gw is None


# -----------------------------------------------------------------------
# RouterAdmin
# -----------------------------------------------------------------------

class TestRouterAdmin:
    def test_not_configured_by_default(self, router_admin):
        assert not router_admin.configured
        assert router_admin.router_ip is None

    def test_configure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "password")
        assert router_admin.configured
        assert router_admin.router_ip == "192.168.1.1"

    def test_hide_ssid_unconfigured(self, router_admin):
        result = asyncio.get_event_loop().run_until_complete(
            router_admin.hide_ssid()
        )
        assert not result["success"]
        assert "not configured" in result["error"].lower()

    def test_show_ssid_unconfigured(self, router_admin):
        result = asyncio.get_event_loop().run_until_complete(
            router_admin.show_ssid()
        )
        assert not result["success"]

    def test_get_visibility_unconfigured(self, router_admin):
        result = asyncio.get_event_loop().run_until_complete(
            router_admin.get_ssid_visibility()
        )
        assert result["state"] == SSIDState.UNKNOWN.value

    def test_detect_type_unconfigured(self, router_admin):
        result = asyncio.get_event_loop().run_until_complete(
            router_admin.detect_router_type()
        )
        assert result == "unknown"

    def test_hide_generic_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "generic"
        # Mock urllib so no real HTTP calls go out
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._hide_generic("all")
        assert not result["success"]
        assert "192.168.1.1" in result["error"]

    def test_show_generic_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "generic"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._show_generic("all")
        assert not result["success"]

    def test_openwrt_login_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        result = router_admin._openwrt_login()
        assert result is None  # No real router to connect to

    def test_hide_openwrt_auth_fail(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "openwrt"
        result = router_admin._hide_openwrt("all")
        assert not result["success"]
        assert "authentication" in result["error"].lower()

    def test_show_openwrt_auth_fail(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "openwrt"
        result = router_admin._show_openwrt("all")
        assert not result["success"]

    def test_hide_ddwrt_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "ddwrt"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._hide_ddwrt("all")
        assert not result["success"]
        assert "DD-WRT" in result["error"]

    def test_show_ddwrt_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._show_ddwrt("all")
        assert not result["success"]

    def test_get_visibility_configured(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        result = router_admin._get_visibility_sync()
        assert result["state"] == SSIDState.UNKNOWN.value

    # -- Nighthawk SOAP tests ------------------------------------------

    def test_nighthawk_login_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._nighthawk_login()
        assert result is False

    def test_nighthawk_login_success(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        resp_body = (
            '<?xml version="1.0"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            '<SOAP-ENV:Body>'
            '<SessionID>ABC123TOKEN</SessionID>'
            '</SOAP-ENV:Body>'
            '</SOAP-ENV:Envelope>'
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = resp_body.encode()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   return_value=mock_resp):
            result = router_admin._nighthawk_login()
        assert result is True
        assert router_admin._session_token == "ABC123TOKEN"

    def test_nighthawk_login_no_session_id(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        resp_body = '<SOAP-ENV:Envelope><SOAP-ENV:Body><OK/></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        mock_resp = MagicMock()
        mock_resp.read.return_value = resp_body.encode()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   return_value=mock_resp):
            result = router_admin._nighthawk_login()
        assert result is True
        assert router_admin._session_token == "authenticated"

    def test_nighthawk_soap_request_success(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._session_token = "TESTTOKEN"
        resp_body = '<ResponseCode>000</ResponseCode>'
        mock_resp = MagicMock()
        mock_resp.read.return_value = resp_body.encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   return_value=mock_resp):
            result = router_admin._nighthawk_soap_request(
                "SetWLANSSIDBroadcast", "<body/>",
                "urn:NETGEAR-ROUTER:service:WLANConfiguration:1",
            )
        assert result == '<ResponseCode>000</ResponseCode>'

    def test_nighthawk_soap_request_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._session_token = "TESTTOKEN"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("timeout")):
            result = router_admin._nighthawk_soap_request(
                "SetWLANSSIDBroadcast", "<body/>",
                "urn:NETGEAR-ROUTER:service:WLANConfiguration:1",
            )
        assert result is None

    def test_nighthawk_soap_request_no_config(self, router_admin):
        result = router_admin._nighthawk_soap_request(
            "SetWLANSSIDBroadcast", "<body/>",
            "urn:NETGEAR-ROUTER:service:WLANConfiguration:1",
        )
        assert result is None

    def test_hide_nighthawk_auth_fail(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "nighthawk"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._hide_nighthawk("all")
        assert not result["success"]
        assert "authentication" in result["error"].lower()

    def test_show_nighthawk_auth_fail(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "nighthawk"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = router_admin._show_nighthawk("all")
        assert not result["success"]
        assert "authentication" in result["error"].lower()

    def test_hide_nighthawk_success(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "nighthawk"
        # Mock: login succeeds, then two SOAP calls succeed (2.4 + 5GHz)
        login_resp = MagicMock()
        login_resp.read.return_value = b'<SessionID>TOK</SessionID>'
        login_resp.status = 200
        login_resp.__enter__ = MagicMock(return_value=login_resp)
        login_resp.__exit__ = MagicMock(return_value=False)

        soap_resp = MagicMock()
        soap_resp.read.return_value = b'<ResponseCode>000</ResponseCode>'
        soap_resp.__enter__ = MagicMock(return_value=soap_resp)
        soap_resp.__exit__ = MagicMock(return_value=False)

        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=[login_resp, soap_resp, soap_resp]):
            result = router_admin._hide_nighthawk("all")
        assert result["success"]
        assert result["action"] == "hidden"
        assert "Nighthawk" in result["message"]

    def test_show_nighthawk_success(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "nighthawk"
        login_resp = MagicMock()
        login_resp.read.return_value = b'<SessionID>TOK</SessionID>'
        login_resp.status = 200
        login_resp.__enter__ = MagicMock(return_value=login_resp)
        login_resp.__exit__ = MagicMock(return_value=False)

        soap_resp = MagicMock()
        soap_resp.read.return_value = b'<ResponseCode>000</ResponseCode>'
        soap_resp.__enter__ = MagicMock(return_value=soap_resp)
        soap_resp.__exit__ = MagicMock(return_value=False)

        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=[login_resp, soap_resp, soap_resp]):
            result = router_admin._show_nighthawk("all")
        assert result["success"]
        assert result["action"] == "visible"
        assert "Nighthawk" in result["message"]

    def test_hide_nighthawk_single_band(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        login_resp = MagicMock()
        login_resp.read.return_value = b'<SessionID>TOK</SessionID>'
        login_resp.status = 200
        login_resp.__enter__ = MagicMock(return_value=login_resp)
        login_resp.__exit__ = MagicMock(return_value=False)

        soap_resp = MagicMock()
        soap_resp.read.return_value = b'<ResponseCode>000</ResponseCode>'
        soap_resp.__enter__ = MagicMock(return_value=soap_resp)
        soap_resp.__exit__ = MagicMock(return_value=False)

        # Only 2.4GHz — login + 1 SOAP call
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=[login_resp, soap_resp]):
            result = router_admin._nighthawk_set_broadcast(False, "2.4")
        assert result["success"]
        assert "2.4GHz" in result["message"]

    def test_hide_nighthawk_partial_failure(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        login_resp = MagicMock()
        login_resp.read.return_value = b'<SessionID>TOK</SessionID>'
        login_resp.status = 200
        login_resp.__enter__ = MagicMock(return_value=login_resp)
        login_resp.__exit__ = MagicMock(return_value=False)

        ok_resp = MagicMock()
        ok_resp.read.return_value = b'<ResponseCode>000</ResponseCode>'
        ok_resp.__enter__ = MagicMock(return_value=ok_resp)
        ok_resp.__exit__ = MagicMock(return_value=False)

        # 2.4GHz succeeds, 5GHz request fails
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=[login_resp, ok_resp,
                                urllib.error.URLError("timeout")]):
            result = router_admin._nighthawk_set_broadcast(False, "all")
        assert result["success"]  # partial success
        assert len(result["details"]) == 2

    def test_detect_nighthawk_type(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'<html>NETGEAR R7000 Nighthawk</html>'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        # First two probes fail (openwrt, ddwrt), third succeeds (nighthawk)
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=[urllib.error.URLError("nope"),
                                urllib.error.URLError("nope"),
                                mock_resp]):
            result = router_admin._detect_type_sync()
        assert result == "nighthawk"

    def test_hide_ssid_dispatches_nighthawk(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "nighthawk"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = asyncio.get_event_loop().run_until_complete(
                router_admin.hide_ssid("all")
            )
        # Should have tried Nighthawk (auth failed)
        assert not result["success"]
        assert "nighthawk" in result["error"].lower() or "authentication" in result["error"].lower()

    def test_show_ssid_dispatches_nighthawk(self, router_admin):
        router_admin.configure("192.168.1.1", "admin", "pass")
        router_admin._detected_type = "nighthawk"
        with patch("network_guardian.cloaking.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = asyncio.get_event_loop().run_until_complete(
                router_admin.show_ssid("all")
            )
        assert not result["success"]


# -----------------------------------------------------------------------
# WiFiStealthSystem
# -----------------------------------------------------------------------

class TestWiFiStealthSystem:
    def test_initial_state(self, stealth):
        assert not stealth._stealth_active
        assert stealth._home_ssid is None
        assert not stealth.router_configured

    def test_stats_initial(self, stealth):
        s = stealth.stats
        assert s["stealth_active"] is False
        assert s["scans"] == 0
        assert s["hide_ops"] == 0
        assert s["show_ops"] == 0

    def test_scan_increments_stats(self, stealth):
        with patch.object(stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=[]):
            asyncio.get_event_loop().run_until_complete(
                stealth.scan_networks()
            )
        assert stealth.stats["scans"] == 1

    def test_scan_returns_networks(self, stealth):
        fake_nets = [
            WiFiNetwork(ssid="Net1", signal=80),
            WiFiNetwork(ssid="Net2", signal=50),
        ]
        with patch.object(stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=fake_nets):
            nets = asyncio.get_event_loop().run_until_complete(
                stealth.scan_networks()
            )
        assert len(nets) == 2
        assert nets[0].ssid == "Net1"

    def test_get_connected_sets_home_ssid(self, stealth):
        fake = WiFiNetwork(ssid="MyHome", signal=90)
        with patch.object(stealth._scanner, "get_connected_network",
                          new_callable=AsyncMock, return_value=fake):
            net = asyncio.get_event_loop().run_until_complete(
                stealth.get_connected_network()
            )
        assert net.ssid == "MyHome"
        assert stealth._home_ssid == "MyHome"

    def test_get_connected_none(self, stealth):
        with patch.object(stealth._scanner, "get_connected_network",
                          new_callable=AsyncMock, return_value=None):
            net = asyncio.get_event_loop().run_until_complete(
                stealth.get_connected_network()
            )
        assert net is None

    def test_detect_gateway(self, stealth):
        with patch.object(stealth._gateway_detector, "detect",
                          new_callable=AsyncMock, return_value="192.168.1.1"):
            gw = asyncio.get_event_loop().run_until_complete(
                stealth.detect_gateway()
            )
        assert gw == "192.168.1.1"

    def test_configure_router(self, stealth):
        with patch.object(stealth._router_admin, "detect_router_type",
                          new_callable=AsyncMock, return_value="generic"):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.configure_router("192.168.1.1", "admin", "pass")
            )
        assert result["success"]
        assert result["router_ip"] == "192.168.1.1"
        assert stealth.router_configured

    def test_configure_router_auto_gateway(self, stealth):
        with patch.object(stealth._gateway_detector, "detect",
                          new_callable=AsyncMock, return_value="10.0.0.1"):
            with patch.object(stealth._router_admin, "detect_router_type",
                              new_callable=AsyncMock, return_value="openwrt"):
                result = asyncio.get_event_loop().run_until_complete(
                    stealth.configure_router(None, "root", "pw")
                )
        assert result["success"]
        assert result["router_ip"] == "10.0.0.1"
        assert result["router_type"] == "openwrt"

    def test_configure_router_no_gateway(self, stealth):
        with patch.object(stealth._gateway_detector, "detect",
                          new_callable=AsyncMock, return_value=None):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.configure_router(None, "admin", "pass")
            )
        assert not result["success"]
        assert "gateway" in result["error"].lower()

    def test_hide_without_router_config(self, stealth):
        with patch.object(stealth._gateway_detector, "detect",
                          new_callable=AsyncMock, return_value="192.168.0.1"):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.hide_network()
            )
        assert not result["success"]
        assert "not configured" in result["error"].lower()

    def test_hide_success(self, stealth):
        stealth._router_admin.configure("192.168.1.1", "admin", "pass")
        with patch.object(stealth._router_admin, "hide_ssid",
                          new_callable=AsyncMock,
                          return_value={"success": True, "message": "Hidden"}):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.hide_network()
            )
        assert result["success"]
        assert stealth._stealth_active
        assert stealth.stats["hide_ops"] == 1

    def test_hide_failure(self, stealth):
        stealth._router_admin.configure("192.168.1.1", "admin", "pass")
        with patch.object(stealth._router_admin, "hide_ssid",
                          new_callable=AsyncMock,
                          return_value={"success": False, "error": "Timeout"}):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.hide_network()
            )
        assert not result["success"]
        assert not stealth._stealth_active

    def test_show_success(self, stealth):
        stealth._router_admin.configure("192.168.1.1", "admin", "pass")
        stealth._stealth_active = True
        with patch.object(stealth._router_admin, "show_ssid",
                          new_callable=AsyncMock,
                          return_value={"success": True, "message": "Visible"}):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.show_network()
            )
        assert result["success"]
        assert not stealth._stealth_active
        assert stealth.stats["show_ops"] == 1

    def test_show_without_config(self, stealth):
        result = asyncio.get_event_loop().run_until_complete(
            stealth.show_network()
        )
        assert not result["success"]

    def test_verify_stealth_hidden(self, stealth):
        stealth._home_ssid = "MyHome"
        # Scan returns networks but NOT our SSID
        other_nets = [WiFiNetwork(ssid="Neighbor", signal=50)]
        with patch.object(stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=other_nets):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.verify_stealth()
            )
        assert result["verified"]
        assert result["hidden"] is True
        assert "NOT visible" in result["message"]

    def test_verify_stealth_visible(self, stealth):
        stealth._home_ssid = "MyHome"
        nets = [WiFiNetwork(ssid="MyHome", signal=90)]
        with patch.object(stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=nets):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.verify_stealth()
            )
        assert result["verified"]
        assert result["hidden"] is False
        assert "still visible" in result["message"]

    def test_verify_unknown_ssid(self, stealth):
        stealth._home_ssid = None
        with patch.object(stealth._scanner, "get_connected_network",
                          new_callable=AsyncMock, return_value=None):
            result = asyncio.get_event_loop().run_until_complete(
                stealth.verify_stealth()
            )
        assert not result["verified"]

    def test_stealth_status(self, stealth):
        fake_net = WiFiNetwork(ssid="Home", signal=85)
        with patch.object(stealth._scanner, "get_connected_network",
                          new_callable=AsyncMock, return_value=fake_net):
            with patch.object(stealth._gateway_detector, "detect",
                              new_callable=AsyncMock, return_value="192.168.1.1"):
                status = asyncio.get_event_loop().run_until_complete(
                    stealth.stealth_status()
                )
        assert status["stealth_active"] is False
        assert status["gateway_ip"] == "192.168.1.1"
        assert status["connected_network"]["ssid"] == "Home"

    def test_stealth_status_no_connection(self, stealth):
        with patch.object(stealth._scanner, "get_connected_network",
                          new_callable=AsyncMock, return_value=None):
            with patch.object(stealth._gateway_detector, "detect",
                              new_callable=AsyncMock, return_value=None):
                status = asyncio.get_event_loop().run_until_complete(
                    stealth.stealth_status()
                )
        assert status["connected_network"] is None
        assert status["gateway_ip"] is None


# -----------------------------------------------------------------------
# Engine integration
# -----------------------------------------------------------------------

class TestEngineWiFiStealth:
    def test_engine_wifi_stealth_property(self):
        engine = Engine()
        ws = engine.wifi_stealth
        assert isinstance(ws, WiFiStealthSystem)

    def test_engine_wifi_stealth_singleton(self):
        engine = Engine()
        ws1 = engine.wifi_stealth
        ws2 = engine.wifi_stealth
        assert ws1 is ws2

    def test_engine_wifi_stealth_has_scanner(self):
        engine = Engine()
        ws = engine.wifi_stealth
        assert isinstance(ws._scanner, WiFiScanner)


# -----------------------------------------------------------------------
# Remote command integration
# -----------------------------------------------------------------------

class TestWiFiRemoteCommands:
    @pytest.fixture
    def router(self):
        from network_guardian.remote import GuardianCommandRouter
        engine = Engine()
        return GuardianCommandRouter(engine)

    def test_wifi_no_args(self, router):
        result = asyncio.get_event_loop().run_until_complete(
            router._cmd_wifi([])
        )
        assert "WiFi Stealth Commands" in result
        assert "wifi scan" in result
        assert "wifi hide" in result

    def test_wifi_scan(self, router):
        fake_nets = [WiFiNetwork(ssid="TestNet", signal=75, security="WPA2", channel=6)]
        with patch.object(router.engine.wifi_stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=fake_nets):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["scan"])
            )
        assert "1 network(s)" in result
        assert "TestNet" in result
        assert "WPA2" in result

    def test_wifi_scan_empty(self, router):
        with patch.object(router.engine.wifi_stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=[]):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["scan"])
            )
        assert "No WiFi networks found" in result

    def test_wifi_status(self, router):
        with patch.object(router.engine.wifi_stealth, "stealth_status",
                          new_callable=AsyncMock,
                          return_value={
                              "stealth_active": False,
                              "home_ssid": "MyHome",
                              "gateway_ip": "192.168.1.1",
                              "router_configured": False,
                              "connected_network": {"ssid": "MyHome", "signal": 90},
                          }):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["status"])
            )
        assert "Stealth: OFF" in result
        assert "MyHome" in result
        assert "192.168.1.1" in result

    def test_wifi_hide_not_configured(self, router):
        with patch.object(router.engine.wifi_stealth, "hide_network",
                          new_callable=AsyncMock,
                          return_value={"success": False, "error": "Router not configured"}):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["hide"])
            )
        assert "not configured" in result.lower()

    def test_wifi_hide_success(self, router):
        with patch.object(router.engine.wifi_stealth, "hide_network",
                          new_callable=AsyncMock,
                          return_value={"success": True, "message": "SSID broadcast disabled"}):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["hide"])
            )
        assert "HIDDEN" in result
        assert "won't appear" in result

    def test_wifi_show_success(self, router):
        with patch.object(router.engine.wifi_stealth, "show_network",
                          new_callable=AsyncMock,
                          return_value={"success": True, "message": "SSID broadcast enabled"}):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["show"])
            )
        assert "VISIBLE" in result

    def test_wifi_verify(self, router):
        with patch.object(router.engine.wifi_stealth, "verify_stealth",
                          new_callable=AsyncMock,
                          return_value={"message": "'MyHome' is NOT visible to nearby devices ✓"}):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["verify"])
            )
        assert "NOT visible" in result

    def test_wifi_router_missing_args(self, router):
        result = asyncio.get_event_loop().run_until_complete(
            router._cmd_wifi(["router"])
        )
        assert "Usage" in result

    def test_wifi_router_configure(self, router):
        with patch.object(router.engine.wifi_stealth, "configure_router",
                          new_callable=AsyncMock,
                          return_value={"success": True, "message": "Router configured: admin@192.168.1.1 (type: generic)"}):
            result = asyncio.get_event_loop().run_until_complete(
                router._cmd_wifi(["router", "192.168.1.1", "admin", "pass"])
            )
        assert "Router configured" in result

    def test_wifi_unknown_subcommand(self, router):
        result = asyncio.get_event_loop().run_until_complete(
            router._cmd_wifi(["foobar"])
        )
        assert "WiFi Stealth Commands" in result

    def test_wifi_in_help(self, router):
        result = router._cmd_help([])
        assert "wifi" in result.lower()

    def test_wifi_in_dispatch(self, router):
        """Ensure 'wifi' is a recognized command."""
        with patch.object(router.engine.wifi_stealth._scanner, "scan_networks",
                          new_callable=AsyncMock, return_value=[]):
            result = asyncio.get_event_loop().run_until_complete(
                router._dispatch("wifi", ["scan"])
            )
        assert "No WiFi" in result or "network" in result.lower()
