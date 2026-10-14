# Replies to encrypted messages from students.
#
# Each run looks in every at26-seminar03-* repository for a public key (XXXXX.pem) and an
# encrypted message (to_instructor.enc). For each message it has not answered yet, it:
#   1. makes the shared secret from the instructor's private key and the student's public key
#   2. decrypts the message, which should be two whole numbers, like "37 + 105"
#   3. writes an encrypted reply with the sum and a random code to the replies folder of
#      this repository
#
# The reply is named after the first 16 hex characters of the SHA-256 hash of the student's
# to_instructor.enc, plus ".enc". So nothing in this public repository says who a reply is
# for. This repository is public and so are its Actions logs, so this script never prints a
# repository name, a user name or a message.
#
# Each student may send five messages. The count is kept in message_counts.json in this
# repository and committed along with the replies. That file is public, so a repository
# appears in it as an HMAC of its name under a key derived from the instructor's private
# key. Without that key the rows cannot be matched to students, or even to each other.
#
# Secrets come in as environment variables, set by the workflow from two Actions secrets.
# There is no keychain on an Actions runner, so there is no keyring option here. To run the
# script line by line instead, set both in the console first, from the keychain.
#   E2E_PRIVATE_KEY  the instructor's X25519 private key, as hex
#   READ_TOKEN       fine-grained token, owner lse-my472, Contents: Read on all repositories

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import urllib.request

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Settings: the organisation, which repositories count, and the words used in reply codes
ORG = "lse-my472"
PREFIX = "at26-seminar03-"
SKIP = {"at26-seminar03-template"}
MESSAGE_FILE = "to_instructor.enc"
COUNTS_FILE = "message_counts.json"
REPLIES_DIR = "replies"
LIMIT = 5
WORDS = ["amber", "anchor", "badger", "cedar", "comet", "copper", "falcon", "harbour",
         "heron", "lantern", "maple", "marble", "meadow", "otter", "pepper", "quartz",
         "raven", "saffron", "thistle", "violet", "walnut", "willow", "zephyr", "tundra"]


def github(path, raw=False):
    # One request to the GitHub API, using the read-only token. Five call sites below.
    request = urllib.request.Request("https://api.github.com" + path)
    request.add_header("Authorization", "Bearer " + os.environ["READ_TOKEN"])
    request.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(request) as response:
        body = json.loads(response.read())
    # A file arrives as base64 inside the JSON. Read files through /git/blobs/{sha}, never
    # through /contents/{path}: the contents endpoint re-encodes the body as text, which
    # destroys an encrypted file, and asking for the raw media type does the same. Tested
    # 2026-10-14: a 36-byte message came back as 58 bytes from contents, 36 from blobs,
    # while contents still reported "size": 36.
    return base64.b64decode(body["content"]) if raw else body


# Load the instructor's private key from the Actions secret
instructor = x25519.X25519PrivateKey.from_private_bytes(
    bytes.fromhex(os.environ["E2E_PRIVATE_KEY"]))

# A separate key for the counts file, so the message key is not also used to make the ids
counts_key = hashlib.sha256(
    b"my472-counts" + bytes.fromhex(os.environ["E2E_PRIVATE_KEY"])).digest()

# The replies all go in one folder, so the root of this repository stays readable
os.makedirs(REPLIES_DIR, exist_ok=True)

# How many messages each repository has sent, written by earlier runs
counts = {}
if os.path.exists(COUNTS_FILE):
    with open(COUNTS_FILE) as f:
        counts = json.load(f)

# Every seminar repository in the organisation, one page of the API listing at a time
repos = []
page = 1
while True:
    batch = github(f"/orgs/{ORG}/repos?type=all&per_page=100&page={page}")
    if not batch:
        break
    repos = repos + [r["name"] for r in batch
                     if r["name"].startswith(PREFIX) and r["name"] not in SKIP]
    page = page + 1

# Totals for the one line this script prints at the end
replied = 0
skipped = 0

# Each student repository in turn: read the key and the message, then write a reply
for name in repos:
    # Five messages each, counted across runs under an id nobody else can work out
    student_id = hmac.new(counts_key, name.encode("utf-8"), hashlib.sha256).hexdigest()[0:16]
    sent = counts.get(student_id, 0)
    if sent >= LIMIT:
        continue

    # List the files at the top level of the repository, keeping the hash of each one
    try:
        shas = {f["name"]: f["sha"] for f in github(f"/repos/{ORG}/{name}/contents/")}
    except Exception:
        skipped = skipped + 1          # empty repository, or no access
        continue
    # The public key and the message must both be there, or there is nothing to answer
    pems = sorted(f for f in shas if re.fullmatch(r"\d{5}\.pem", f))
    if MESSAGE_FILE not in shas or not pems:
        continue

    # Fetch the message. Its hash names the reply, so each message is answered once
    try:
        message = github(f"/repos/{ORG}/{name}/git/blobs/{shas[MESSAGE_FILE]}", raw=True)
    except Exception:
        skipped = skipped + 1          # could not fetch the message this run
        continue
    reply_name = hashlib.sha256(message).hexdigest()[0:16] + ".enc"
    reply_path = os.path.join(REPLIES_DIR, reply_name)
    if os.path.exists(reply_path):
        continue                       # already answered

    # Make the shared secret from the instructor's private key and the student's public key
    try:
        student_public = serialization.load_pem_public_key(
            github(f"/repos/{ORG}/{name}/git/blobs/{shas[pems[0]]}", raw=True))
        shared_secret = instructor.exchange(student_public)
    except Exception:
        skipped = skipped + 1          # not a valid X25519 public key
        continue

    # Decrypt: the first 12 bytes are the initialisation vector, the rest ciphertext and tag
    # A usable message is at least a 12-byte initialisation vector plus a 16-byte tag
    if len(message) < 28:
        plaintext = None
    else:
        try:
            plaintext = AESGCM(shared_secret).decrypt(
                message[0:12], message[12:], None).decode("utf-8", errors="replace")
        except (InvalidTag, ValueError):
            plaintext = None           # wrong shared secret, or a file we cannot read

    # Look for two whole numbers added together
    sum_parts = None
    if plaintext is not None:
        sum_parts = re.fullmatch(r"\s*(-?\d+)\s*\+\s*(-?\d+)\s*", plaintext)

    # The reply: could not decrypt, could not read a sum, or the answer
    if plaintext is None:
        text = ("I could not decrypt your message. Check that you made the shared secret "
                "from your private key and my public key, and that the file is the "
                "initialisation vector followed by the ciphertext and tag.")
    elif sum_parts is None:
        text = (f"I could not read a sum in your message: {plaintext[0:100]!r}. "
                f"Send two whole numbers in the form 37 + 105.")
    else:
        a = int(sum_parts.group(1))
        b = int(sum_parts.group(2))
        # Three random words and a random number, so every reply is different
        code = " ".join(secrets.choice(WORDS) for _ in range(3)) + " " + str(secrets.randbelow(900) + 100)
        text = f"{a} + {b} = {a + b}. Your code is {code}."

    # Say so on the last reply they are allowed
    if sent + 1 >= LIMIT:
        text = text + (" You have sent five messages. You will not receive a reply if you "
                       "send any more.")

    # Encrypt the reply and write it into this repository
    iv = os.urandom(12)
    with open(reply_path, mode="wb") as f:
        f.write(iv + AESGCM(shared_secret).encrypt(iv, text.encode("utf-8"), None))
    counts[student_id] = sent + 1
    replied = replied + 1

# Keep the counts for the next run
with open(COUNTS_FILE, mode="w") as f:
    json.dump(counts, f, indent=2, sort_keys=True)

print(f"Replies written: {replied}. Repositories skipped: {skipped}.")
