"""Print the app's declared option defaults as JSON, with a manager address added.

Used by the render tests to prove the renderer's built-in fallbacks match config.yaml.
"""

import json
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    config = yaml.safe_load(handle)

options = dict(config["options"])
options["manager_address"] = "wazuh.example.lan"
print(json.dumps(options))
