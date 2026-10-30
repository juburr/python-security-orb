"""A fixture with nothing for Bandit to find."""

import hashlib
import subprocess


def run(arguments):
    return subprocess.run(arguments, check=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()
