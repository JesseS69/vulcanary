from __future__ import annotations

import argparse
from pathlib import Path

from vulcanary.corpus_metrics import write_comparison


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two Vulcanary experimental-dataflow corpus reports.")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    write_comparison(args.baseline, args.candidate, args.output)


if __name__ == "__main__":
    main()
