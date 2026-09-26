"""honest-watchdogs: monitoring instruments that prove they can fire.

Every instrument in this package follows one exit-code convention:

    0  OK             measured, and nothing is wrong
    1  FINDINGS       measured, and something is wrong
    2  MISCONFIGURED  the instrument's own configuration is wrong (argparse usage errors too)
    3  UNKNOWN        could not measure; this is never reported as OK

When both findings and unknowns are present, UNKNOWN wins: "I could not look" must never be
reported as "I looked".
"""

__version__ = "1.0.0"
