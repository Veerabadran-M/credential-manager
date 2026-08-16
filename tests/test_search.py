"""Tests for per-field matching (services/accounts) and global free-text
search across service names, userids, and notes.
"""

from __future__ import annotations

import pytest

from credmgr.models import Account, Credentials
from credmgr.schemas.base import SchemaError
from credmgr.search import (global_search, resolve_for_mutation,
                             search_accounts, search_services)


def _creds():
    creds = Credentials()
    creds.services["github"] = [Account(userid="alice", password="p1", notes="work account")]
    creds.services["gitlab"] = [Account(userid="bob", password="p2", notes="")]
    creds.services["netflix"] = [Account(userid="carol", password="p3", notes="family plan")]
    return creds


# ---- search_services ----

def test_search_services_exact_match():
    creds = _creds()
    assert search_services(creds, "github") == ["github"]


def test_search_services_partial_case_insensitive_match():
    creds = _creds()
    result = search_services(creds, "GIT")
    assert set(result) == {"github", "gitlab"}


def test_search_services_fuzzy_match_on_typo():
    creds = _creds()
    # "netflx" is a one-character-off typo of "netflix"; no exact or
    # substring match exists, so this must fall through to fuzzy matching.
    result = search_services(creds, "netflx")
    assert "netflix" in result


def test_search_services_no_match_returns_empty():
    creds = _creds()
    assert search_services(creds, "totally-unrelated-xyz") == []


def test_search_services_exact_match_takes_priority_over_partial():
    creds = Credentials()
    creds.services["git"] = [Account(userid="a", password="p", notes="")]
    creds.services["github"] = [Account(userid="b", password="p", notes="")]
    # "git" is both an exact match and a substring of "github"; exact wins.
    assert search_services(creds, "git") == ["git"]


# ---- search_accounts ----

def test_search_accounts_exact_case_insensitive_match():
    accounts = [Account(userid="Alice", password="p", notes="")]
    result = search_accounts(accounts, "alice")
    assert result == accounts


def test_search_accounts_partial_match():
    accounts = [
        Account(userid="alice.smith", password="p", notes=""),
        Account(userid="bob", password="p", notes=""),
    ]
    result = search_accounts(accounts, "alice")
    assert len(result) == 1
    assert result[0].userid == "alice.smith"


def test_search_accounts_no_match():
    accounts = [Account(userid="alice", password="p", notes="")]
    assert search_accounts(accounts, "nobody") == []


# ---- resolve_for_mutation ----

def test_resolve_for_mutation_unknown_service_raises():
    creds = _creds()
    with pytest.raises(SchemaError, match="not found"):
        resolve_for_mutation(creds, "doesnotexist", None)


def test_resolve_for_mutation_ambiguous_service_raises():
    creds = _creds()
    with pytest.raises(SchemaError, match="Ambiguous"):
        resolve_for_mutation(creds, "git", None)


def test_resolve_for_mutation_without_userid_returns_all_accounts():
    creds = _creds()
    result = resolve_for_mutation(creds, "github", None)
    assert result is not None
    svc, accounts, acc = result
    assert svc == "github"
    assert acc is None
    assert accounts == creds.services["github"]


def test_resolve_for_mutation_with_userid_returns_matching_account():
    creds = _creds()
    svc, accounts, acc = resolve_for_mutation(creds, "github", "alice")
    assert svc == "github"
    assert acc.userid == "alice"


def test_resolve_for_mutation_unknown_userid_raises():
    creds = _creds()
    with pytest.raises(SchemaError, match="No account"):
        resolve_for_mutation(creds, "github", "nobody")


# ---- global_search ----

def test_global_search_matches_service_name():
    creds = _creds()
    results = global_search(creds, "github")
    assert len(results) == 1
    service, acc, field_hit = results[0]
    assert service == "github"
    assert field_hit == "service"


def test_global_search_matches_userid():
    creds = _creds()
    results = global_search(creds, "carol")
    assert len(results) == 1
    service, acc, field_hit = results[0]
    assert service == "netflix"
    assert field_hit == "userid"


def test_global_search_matches_notes():
    creds = _creds()
    results = global_search(creds, "family")
    assert len(results) == 1
    service, acc, field_hit = results[0]
    assert service == "netflix"
    assert field_hit == "notes"


def test_global_search_no_match_returns_empty_list():
    creds = _creds()
    assert global_search(creds, "nonexistent-query-xyz") == []


def test_global_search_query_matching_multiple_services_returns_all():
    creds = _creds()
    results = global_search(creds, "git")
    services_hit = {r[0] for r in results}
    assert services_hit == {"github", "gitlab"}
