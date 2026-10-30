"""A fixture with the problems Bandit finds. Never run it."""

import hashlib
import pickle
import subprocess


def run(command):
    return subprocess.call(command, shell=True)


def digest(data):
    return hashlib.md5(data).hexdigest()


def load(blob):
    return pickle.loads(blob)  # nosec B301


def scratch():
    return open("/tmp/fixture-scratch", "w")  # nosec B108 # a fixed path in a test fixture
