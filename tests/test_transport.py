"""Tests for MCP transport and HTTP configuration handling."""
import os
from unittest.mock import patch

import pytest

from mssql_mcp_server.server import get_http_config, get_transport


class TestTransportConfig:
    """Test MCP transport selection."""

    def test_get_transport_defaults_to_stdio(self):
        """Default transport should be stdio."""
        with patch.dict(os.environ, {}, clear=True):
            assert get_transport() == "stdio"

    def test_get_transport_http_alias(self):
        """HTTP alias should map to streamable-http."""
        with patch.dict(os.environ, {"MCP_TRANSPORT": "http"}, clear=True):
            assert get_transport() == "streamable-http"

    def test_get_transport_invalid_value(self):
        """Invalid transport value should raise an error."""
        with patch.dict(os.environ, {"MCP_TRANSPORT": "invalid"}, clear=True):
            with pytest.raises(ValueError, match="Invalid MCP_TRANSPORT value"):
                get_transport()


class TestHttpConfig:
    """Test HTTP server configuration parsing."""

    def test_get_http_config_defaults(self):
        """Default HTTP configuration values."""
        with patch.dict(os.environ, {}, clear=True):
            config = get_http_config()
            assert config["host"] == "127.0.0.1"
            assert config["port"] == 8000
            assert config["mcp_path"] == "/mcp"
            assert config["sse_path"] == "/sse"
            assert config["message_path"] == "/messages"
            assert config["stateless_http"] is False

    def test_get_http_config_normalizes_paths(self):
        """Path settings should be normalized to leading slash."""
        with patch.dict(
            os.environ,
            {
                "MCP_PATH": "api/mcp",
                "MCP_SSE_PATH": "events",
                "MCP_MESSAGE_PATH": "messages",
            },
            clear=True,
        ):
            config = get_http_config()
            assert config["mcp_path"] == "/api/mcp"
            assert config["sse_path"] == "/events"
            assert config["message_path"] == "/messages"

    def test_get_http_config_invalid_port(self):
        """Invalid MCP_PORT should raise an error."""
        with patch.dict(os.environ, {"MCP_PORT": "not-a-number"}, clear=True):
            with pytest.raises(ValueError, match="Invalid MCP_PORT value"):
                get_http_config()
