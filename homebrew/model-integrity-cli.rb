# typed: true
# frozen_string_literal: true

# ─────────────────────────────────────────────────────────────────────────
# Homebrew formula for Sentinel — AI Model Runtime Integrity Checker
#
# Install:
#   brew tap model-integrity-cli/sentinel
#   brew install model-integrity-cli
#
# Or from a local checkout:
#   brew install --formula homebrew/model-integrity-cli.rb
# ─────────────────────────────────────────────────────────────────────────

class ModelIntegrityCli < Formula
  include Language::Python::Virtualenv

  desc "AI Model Runtime Integrity Checker — pre/post system state checksums"
  homepage "https://github.com/model-integrity-cli/sentinel"
  url "https://files.pythonhosted.org/packages/source/m/model-integrity-cli/model_integrity_cli-0.1.0.tar.gz"
  sha256 "8047c17f3b9150109990b3ee4387652b80ed1a41401b963a146ab336f07df34d"
  license "MIT"

  depends_on "python@3.11"

  # No external Python dependencies — Sentinel is pure stdlib.
  # The virtualenv_install_with_resources call handles the package itself.

  def install
    virtualenv_install_with_resources
  end

  test do
    # Quick smoke test
    output = shell_output("#{bin}/sentinel --version")
    assert_match "sentinel 0.1.0", output

    # Verify all subcommands parse
    output = shell_output("#{bin}/sentinel --help")
    %w[snapshot run diff list allow status sign verify daemon dashboard incidents].each do |cmd|
      assert_match cmd, output
    end
  end
end
