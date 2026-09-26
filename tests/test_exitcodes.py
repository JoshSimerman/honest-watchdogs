from honest_watchdogs.exitcodes import (
    EXIT_FINDINGS,
    EXIT_MISCONFIGURED,
    EXIT_OK,
    EXIT_UNKNOWN,
    combine,
)


def test_codes_are_distinct_and_unknown_is_not_ok() -> None:
    codes = {EXIT_OK, EXIT_FINDINGS, EXIT_MISCONFIGURED, EXIT_UNKNOWN}
    assert len(codes) == 4
    assert EXIT_UNKNOWN != EXIT_OK


def test_unknown_outranks_findings() -> None:
    """'I could not look' must never be reported as 'I looked and found X'."""
    assert combine(EXIT_FINDINGS, EXIT_UNKNOWN) == EXIT_UNKNOWN
    assert combine(EXIT_UNKNOWN, EXIT_OK, EXIT_FINDINGS) == EXIT_UNKNOWN


def test_findings_outrank_ok_and_misconfigured() -> None:
    assert combine(EXIT_OK, EXIT_FINDINGS) == EXIT_FINDINGS
    assert combine(EXIT_MISCONFIGURED, EXIT_FINDINGS) == EXIT_FINDINGS
    assert combine() == EXIT_OK


def test_an_unrecognised_code_is_treated_as_unknown() -> None:
    assert combine(EXIT_OK, 70) == EXIT_UNKNOWN
