#!/usr/bin/env python3
"""Check actual target providers and eager relocation; never infer ABI by distro number."""
import ctypes
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from artifacts import check_elf_versions

if len(sys.argv) != 2:
    raise SystemExit('usage: check_abi.py /absolute/path/to/libdave.so')
library = Path(sys.argv[1]).resolve(strict=True)
evidence = check_elf_versions([library])
ctypes.CDLL(str(library), mode=os.RTLD_NOW)
print(json.dumps(evidence, indent=2, sort_keys=True))
