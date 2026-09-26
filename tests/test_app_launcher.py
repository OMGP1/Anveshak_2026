"""Check developer-facing startup failures without starting a second engine."""
import socket

import app


def test_occupied_port_reports_the_listener_command(monkeypatch, capsys):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        monkeypatch.setenv("SIH_API_PORT", str(port))
        assert app.main() == 1
    error = capsys.readouterr().err
    assert f"Cannot start the API on 127.0.0.1:{port}" in error
    assert f"Get-NetTCPConnection -LocalPort {port}" in error
    assert "/simple/" in error


def test_invalid_port_explains_the_valid_range(monkeypatch, capsys):
    for value in ("wrong", "0", "65536"):
        monkeypatch.setenv("SIH_API_PORT", value)
        assert app.main() == 1
        assert "between 1 and 65535" in capsys.readouterr().err
