import argparse
from .config import SEVERITY_ORDER , DEFAULT_CONFIG
import json
from .agent import deep_merge , SentinelAgent
import signal
import sys
from .logger import Logger




logger = Logger.get_logger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Sentinel Security Log Agent")
    parser.add_argument("--config",   help="Path to config JSON", default=None)
    parser.add_argument("--log-dir",  help="Output log directory", default=None)
    parser.add_argument("--stdout",   help="Also print events to stdout", action="store_true")
    parser.add_argument("--no-file",  help="Disable file collector", action="store_true")
    parser.add_argument("--no-auth",  help="Disable auth collector", action="store_true")
    parser.add_argument("--no-net",   help="Disable network collector", action="store_true")
    parser.add_argument("--no-proc",  help="Disable process collector", action="store_true")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default=None)
    args = parser.parse_args()

   
    config = DEFAULT_CONFIG.copy()

    if args.config:
        with open(args.config) as f:
            user_config = json.load(f)
        config = deep_merge(config, user_config)

    if args.log_dir:
        config["output"]["log_dir"] = args.log_dir
    if args.stdout:
        config["output"]["stdout"] = True
    if args.no_file:
        config["collectors"]["file"]["enabled"] = False
    if args.no_auth:
        config["collectors"]["auth"]["enabled"] = False
    if args.no_net:
        config["collectors"]["network"]["enabled"] = False
    if args.no_proc:
        config["collectors"]["process"]["enabled"] = False
    if args.min_severity:
        config["filters"]["min_severity"] = args.min_severity

    agent = SentinelAgent(config)

    def _sig_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT,  _sig_handler)

    agent.start()
    agent.wait()


if __name__ == "__main__":
    main()
