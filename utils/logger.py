import logging
import os

def get_logger(name, filename="system.log"):
    log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
    os.makedirs(log_dir, exist_ok=True)
    file_path = os.path.join(log_dir, filename)

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.FileHandler(file_path)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
