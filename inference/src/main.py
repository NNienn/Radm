# inference/src/main.py
import asyncio
import argparse
import yaml
import logging
import sys
from pathlib import Path

# Add src to python path to resolve local imports
sys.path.insert(0, str(Path(__file__).parent))

from detector import run_detector

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="radm.yaml", help="Path to config YAML")
    args = parser.parse_args()
    
    config_path = Path(args.config)
    if not config_path.exists():
        # Try parent directory relative to script
        config_path = Path(__file__).parent.parent / args.config

    with open(config_path) as f:
        cfg = yaml.safe_load(f)
        
    asyncio.run(run_detector(cfg))
