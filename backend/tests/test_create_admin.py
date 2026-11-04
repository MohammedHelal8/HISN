
from unittest.mock import patch

from scripts.create_admin import main


def test_empty_admin_username(capsys):
    with patch("builtins.input", return_value=""):
        main()

    output = capsys.readouterr().out

    assert "Username must contain" in output


def test_password_mismatch(capsys):
    with (
        patch("builtins.input", return_value="test_admin"),
        patch(
            "getpass.getpass",
            side_effect=[
                "Strong-Test-Password-2026!",
                "Different-Test-Password-2026!",
            ],
        ),
    ):
        main()

    output = capsys.readouterr().out

    assert "Passwords do not match" in output


def test_short_password(capsys):
    with (
        patch("builtins.input", return_value="test_admin"),
        patch(
            "getpass.getpass",
            side_effect=["short", "short"],
        ),
    ):
        main()

    output = capsys.readouterr().out

    assert "Password must contain at least 12" in output
