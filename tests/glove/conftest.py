"""Test bootstrap: make the repo root importable so `import glove` works
when pytest is invoked from anywhere (the package lives at the repo root).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
