"""The exit-code convention shared by every instrument.

UNKNOWN is deliberately a distinct, non-zero code. A scheduler, a shell pipeline or a human
reading ``$?`` must be able to tell "measured and healthy" from "could not measure" without
parsing any output.
"""

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_MISCONFIGURED = 2
EXIT_UNKNOWN = 3


def combine(*codes: int) -> int:
    """Fold several verdicts into one, with UNKNOWN outranking everything.

    Precedence: UNKNOWN > FINDINGS > MISCONFIGURED > OK. A finding elsewhere must never mask
    the fact that some part of the survey could not be measured.
    """

    order = {EXIT_UNKNOWN: 3, EXIT_FINDINGS: 2, EXIT_MISCONFIGURED: 1, EXIT_OK: 0}
    best = EXIT_OK
    for code in codes:
        if order.get(code, 3) > order.get(best, 3):
            best = code if code in order else EXIT_UNKNOWN
    return best
