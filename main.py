#!/usr/bin/env python3

import argparse
import os
import sys

from detection.detection_engine import AirSentinelEngine


def main():
    parser = argparse.ArgumentParser(
        description="AirSentinel Live Detection"
    )

    parser.add_argument("--model", required=True,
                        help="Path to trained model (.joblib/.pkl)")
    parser.add_argument("--scaler", required=True,
                        help="Path to scaler (.joblib/.pkl)")
    parser.add_argument("--interface", default="wlan0mon",
                        help="Monitor interface (default: wlan0mon)")
    parser.add_argument("--threshold", type=float, default=-0.3,
                        help="Anomaly threshold (default: -0.3)")
    parser.add_argument("--min-packets", type=int, default=10,
                        help="Minimum packets before detection (default: 10)")
    parser.add_argument("--duration", type=int,
                        help="Run duration in seconds (default: continuous)")
    parser.add_argument("--channels",
                    help="Comma separated channel list (e.g. 1,6,11)")

    args = parser.parse_args()

    # Root check (required for monitor mode)
    if os.geteuid() != 0:
        print("Must run as root (sudo).")
        sys.exit(1)

    engine = AirSentinelEngine(
        model_path=args.model,
        scaler_path=args.scaler,
        min_packets=args.min_packets,
        alert_threshold=args.threshold
    )

    engine.start(
        interface=args.interface,
        duration=args.duration,
        channels=args.channels
    )


if __name__ == "__main__":
    main()