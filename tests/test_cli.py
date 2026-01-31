from __future__ import annotations

from kakveda_cli.cli import main


def test_cli_help(capsys):
    try:
        main(["init", "--help"])
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    assert "usage:" in out
    assert "--force" in out


def test_cli_parser_errors():
    # Missing subcommand should exit with SystemExit from argparse
    try:
        main([])
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code != 0


def test_cli_help_top_level(capsys):
    try:
        main(["--help"])
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    assert "kakveda" in out
    assert "init" in out
    assert "up" in out
    assert "down" in out
    assert "status" in out
    assert "reset" in out
