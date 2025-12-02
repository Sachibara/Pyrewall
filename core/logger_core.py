"""
Centralized logging for firewall engine and UI.
"""

import logging
import os

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

def setup_logger(name, filename):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(os.path.join(LOG_DIR, filename))
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)
    return logger

firewall_logger = setup_logger("firewall", "firewall.log")
system_logger = setup_logger("system", "system.log")
alert_logger = setup_logger("alerts", "alerts.log")
