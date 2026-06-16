from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from detector import run_detector


def load_config(path: Path) -> dict:
    if not path.exists():
        path = Path(__file__).parent.parent / path.name
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="radm.yaml", help="Path to config YAML")
    args = parser.parse_args()

    asyncio.run(run_detector(load_config(Path(args.config))))
