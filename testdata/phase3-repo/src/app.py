import requests, subprocess, pickle, hashlib

DEBUG = True

def fetch(url):
    return requests.get(url, verify=False)

def run(cmd):
    subprocess.call("ls " + cmd, shell=True)

def query(db, user):
    return db.execute("SELECT * FROM users WHERE name = '" + user + "'")

def load(blob):
    return pickle.loads(blob)

def check(pw, stored):
    return hashlib.md5(pw.encode()).hexdigest() == stored  # password hash
