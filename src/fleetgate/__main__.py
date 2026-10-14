"""`python -m fleetgate` is the same as the `fleetgate` command."""
import sys

from .cli import main

sys.exit(main())
