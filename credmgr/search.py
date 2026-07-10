"""Search: per-field fuzzy matching (services/accounts) plus a global
free-text search engine across service names, userids, and notes.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from .config import config
from .models import Credentials

def _fuzzy_score(query: str, value: str) -> float:
    """Return the best fuzzy score for a field.

    For longer free-text fields like notes, comparing the query to each word
    catches typo-level matches without requiring the whole note to resemble
    the query.
    """
    query = query.lower()
    value = (value or "").lower()
    if not query or not value:
        return 0.0

    candidates = [value, *re.findall(r"\w+", value)]
    return max(SequenceMatcher(None, query, candidate).ratio() for candidate in candidates)

def search_services(creds: Credentials, query: str) -> list:
    data = creds.services

    # Exact match
    if query in data:
        return [query]

    # Partial match (case-insensitive substring)
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    partial = [svc for svc in data if pattern.search(svc)]
    if partial:
        return partial

    # Fuzzy match (SequenceMatcher ratio)
    scored = [(SequenceMatcher(None, query.lower(), svc.lower()).ratio(), svc) for svc in data]
    return [svc for score, svc in sorted(scored, reverse=True) if score >= config.fuzzy_threshold]

def search_accounts(accounts: list, query: str) -> list:
    # Exact match (case-insensitive)
    exact = [acc for acc in accounts if acc.userid.lower() == query.lower()]
    if exact:
        return exact

    # Partial match (case-insensitive substring)
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    return [acc for acc in accounts if pattern.search(acc.userid)]

def resolve_for_mutation(creds: Credentials, service: str, userid):
    """Resolve a service (+ optional userid) for commands that mutate the vault."""
    from .ui import console  # local import avoids a circular import at module load time

    matched_services = search_services(creds, service)
    if not matched_services:
        console.print(f"Service '{service}' not found.", style="bold red")
        return None
    if len(matched_services) > 1:
        console.print(
            f"Ambiguous service '{service}'. Be more specific. "
            f"Matches: {', '.join(matched_services)}",
            style="bold yellow"
        )
        return None
    svc = matched_services[0]
    accounts = creds.services[svc]

    if userid is None:
        return svc, accounts, None

    matched_accounts = search_accounts(accounts, userid)
    if not matched_accounts:
        console.print(f"No account '{userid}' under '{svc}'.", style="bold red")
        return None
    if len(matched_accounts) > 1:
        console.print(
            f"Ambiguous userid '{userid}'. Be more specific. "
            f"Matches: {', '.join(a.userid for a in matched_accounts)}",
            style="bold yellow"
        )
        return None

    return svc, accounts, matched_accounts[0]

def global_search(creds: Credentials, query: str):
    """Free-text search across service names, userids, and notes.

    Returns a list of (service, Account, matched_field) tuples.
    """
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    results = []

    for service, accounts in creds.services.items():
        service_hit = bool(pattern.search(service))
        service_fuzzy = _fuzzy_score(query, service) >= config.fuzzy_threshold
        for acc in accounts:
            if service_hit:
                results.append((service, acc, "service"))
            elif pattern.search(acc.userid):
                results.append((service, acc, "userid"))
            elif pattern.search(acc.notes or ""):
                results.append((service, acc, "notes"))
            elif service_fuzzy:
                results.append((service, acc, "service"))
            elif _fuzzy_score(query, acc.userid) >= config.fuzzy_threshold:
                results.append((service, acc, "userid"))
            elif _fuzzy_score(query, acc.notes or "") >= config.fuzzy_threshold:
                results.append((service, acc, "notes"))

    return results
