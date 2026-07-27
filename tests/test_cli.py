"""Tests for the CLI interface."""

from sentinel.cli import build_parser


class TestParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_parse_snapshot(self):
        args = self.parser.parse_args(["snapshot", "--label", "test", "--path", "/extra"])
        assert args.command == "snapshot"
        assert args.label == "test"
        assert args.paths == ["/extra"]

    def test_parse_run(self):
        args = self.parser.parse_args([
            "run",
            "--label", "llama",
            "--model-dir", "/models/llama",
            "--timeout", "300",
            "--format", "json",
            "./run.sh",
        ])
        assert args.command == "run"
        assert args.label == "llama"
        assert args.model_dir == ["/models/llama"]
        assert args.timeout == 300
        assert args.format == "json"
        assert args.cmd == "./run.sh"

    def test_parse_diff(self):
        args = self.parser.parse_args(["diff", "pre.json", "post.json"])
        assert args.command == "diff"
        assert args.pre == "pre.json"
        assert args.post == "post.json"

    def test_parse_list(self):
        args = self.parser.parse_args(["list"])
        assert args.command == "list"

    def test_parse_allow_add(self):
        args = self.parser.parse_args(["allow", "--add", "/etc/some/path"])
        assert args.command == "allow"
        assert args.add == "/etc/some/path"

    def test_parse_allow_remove(self):
        args = self.parser.parse_args(["allow", "--remove", "/etc/some/path"])
        assert args.command == "allow"
        assert args.remove == "/etc/some/path"

    def test_parse_status(self):
        args = self.parser.parse_args(["status"])
        assert args.command == "status"

    def test_no_command_shows_help(self):
        args = self.parser.parse_args([])
        assert args.command is None
