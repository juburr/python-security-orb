"""A fixture with nothing for Bandit to find."""

import hashlib
import json


def load(text):
    return json.loads(text)


def digest(data):
    return hashlib.sha256(data).hexdigest()
