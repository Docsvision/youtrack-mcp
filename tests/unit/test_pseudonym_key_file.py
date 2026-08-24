"""Tests for loading the sanitizer pseudonym key from a Docker secret file."""

import pytest

from sanitizer_service.service import Pseudonymizer


@pytest.mark.unit
def test_pseudonymizer_reads_key_file(monkeypatch, tmp_path):
    key_file = tmp_path / "pseudonym.key"
    key_file.write_text("stable-secret\n", encoding="utf-8")
    monkeypatch.delenv("SANITIZER_PSEUDONYM_KEY", raising=False)
    monkeypatch.setenv("SANITIZER_PSEUDONYM_KEY_FILE", str(key_file))

    assert Pseudonymizer().alias("Ivan") == Pseudonymizer("stable-secret").alias("Ivan")


@pytest.mark.unit
def test_pseudonymizer_rejects_empty_key_file(monkeypatch, tmp_path):
    key_file = tmp_path / "pseudonym.key"
    key_file.write_text("", encoding="utf-8")
    monkeypatch.delenv("SANITIZER_PSEUDONYM_KEY", raising=False)
    monkeypatch.setenv("SANITIZER_PSEUDONYM_KEY_FILE", str(key_file))

    with pytest.raises(ValueError, match="is empty"):
        Pseudonymizer()
