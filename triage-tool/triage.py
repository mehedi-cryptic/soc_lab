#!/usr/bin/env python3
"""Run the SOC alert triage tool. See README.md for usage."""

import sys

from soctriage.cli import main

if __name__ == "__main__":
    sys.exit(main())
