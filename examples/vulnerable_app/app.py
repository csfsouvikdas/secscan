"""INTENTIONALLY VULNERABLE demo app for SecScan. All secrets are fake. Never deploy this."""
import hashlib
import pickle
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "SuperSecret123"
SESSION_SIGNING_KEY = "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"


@app.route("/user")
def get_user():
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    row = db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchone()
    return str(row)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello " + request.args.get("n", "") + "</h1>")


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return str((obj, cfg))


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def fetch(url):
    try:
        return requests.get(url, verify=False).text
    except Exception:
        pass


def scratch():
    return tempfile.mktemp()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
