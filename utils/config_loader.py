import json
import os

def load_json_config(filename):
    path = os.path.join(os.path.dirname(__file__), "..", "config", filename)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)
