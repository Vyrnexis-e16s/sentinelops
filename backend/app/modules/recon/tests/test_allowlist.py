"""Recon allowlist (RECON_TARGET_ALLOWLIST) behaviour."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.modules.recon import allowlist as al


@pytest.fixture(autouse=True)
def _restore_settings() -> None:
    real = al.settings
    yield
    al.settings = real


def test_empty_allowlist_allows_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(al, "settings", SimpleNamespace(recon_target_allowlist="  "))
    assert al.target_matches_allowlist("8.8.8.8") is True
    assert al.target_matches_allowlist("any.example.com") is True


def test_domain_suffix_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        al, "settings", SimpleNamespace(recon_target_allowlist="lab.local, example.com")
    )
    assert al.target_matches_allowlist("host.lab.local") is True
    assert al.target_matches_allowlist("www.example.com") is True
    assert al.target_matches_allowlist("example.com") is True
    assert al.target_matches_allowlist("other.org") is False


def test_ip_in_cidr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(al, "settings", SimpleNamespace(recon_target_allowlist="10.0.0.0/8"))
    assert al.target_matches_allowlist("10.1.2.3") is True
    assert al.target_matches_allowlist("8.8.8.8") is False


def test_cidr_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(al, "settings", SimpleNamespace(recon_target_allowlist="10.0.0.0/8"))
    assert al.target_matches_allowlist("10.0.0.0/16") is True
    assert al.target_matches_allowlist("10.0.0.0/24") is True
