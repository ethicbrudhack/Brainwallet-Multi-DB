🧠 Brainwallet Multi-DB

⚠️ Educational / Research Use Only — Untested Prototype
This script is a prototype and has not been fully tested. It may contain bugs or logic errors. Use at your own risk and only in a safe, offline environment. Do not use this tool to try to access wallets, funds, or private keys you do not own.

Overview

brainwallet_multi_db.py is a classic brainwallet generator with per-phrase variants. For each input passphrase it generates VARIANTS derived private keys (and addresses) using SHA-256:

variant 0 = SHA256(passphrase) (classic brainwallet)

variant 1..N = SHA256(passphrase + str(index))

All generated addresses and keys are saved into a local SQLite database (by default generated_addresses2.db). Optionally, each generated address is checked against an external read-only SQLite database of known addresses (by default alladdresses.db) and hits are logged immediately.

This tool is intended for educational or research use (e.g., to study address derivation), not for unauthorized access or malicious activity.

Features

Generates multiple private-key variants per passphrase.

Derives uncompressed ECDSA (secp256k1) public key and Bitcoin P2PKH address.

Saves every generated record to an SQLite DB (generated table) for later analysis.

Optionally checks addresses against an external SQLite addresses table (read-only).

Batch commits to the generated DB for performance.

Simple CLI-friendly default behavior (no external frameworks required).

Quickstart & Usage
Requirements
pip install ecdsa base58

Usage
python3 brainwallet_multi_db.py [input_file] [output_csv] [check_db] [gen_db]


Defaults used when arguments are omitted:

input_file → slowadobrainwallet.txt

output_csv → result1s.csv

check_db → alladdresses.db (read-only address DB, optional)

gen_db → generated_addresses2.db (where generated addresses are saved)

Example:

python3 brainwallet_multi_db.py wordlist.txt results.csv alladdresses.db generated.db

Generated DB Schema

init_generated_db() creates (if missing) the generated table:

CREATE TABLE IF NOT EXISTS generated (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  line INTEGER,
  variant INTEGER,
  passphrase TEXT,
  address TEXT,
  wif TEXT,
  priv_hex TEXT,
  created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_generated_address ON generated(address);


FOUND_FILENAME (default: znalazlembrainwallet1.txt) receives hits found while checking the external check_db.

Important Configuration Constants (top of script)

DB_PATH_DEFAULT — path to check DB (read-only)

GEN_DB_DEFAULT — path for storing generated records

FOUND_FILENAME — file to append hits into

VARIANTS — number of variants generated per passphrase (default in the script: 100)

PROGRESS_INTERVAL — how frequently progress is printed

DB_RETRIES, DB_BACKOFF_BASE, DB_TIMEOUT — resilience for SQLite locking

Output

generated_addresses2.db — contains all generated records (if default)

znalazlembrainwallet1.txt — appended on each hit (address found in the check_db)

result1s.csv — CSV export of run results (line, variant, passphrase, address, wif, priv_hex)

Security & Ethical Notice

This script deals with private keys. Treat any private keys produced or stored as highly sensitive information.

Do not run this tool targeting databases or addresses you do not own or have explicit permission to test. Attempting to access others’ funds is illegal and unethical.

Consider running in an air-gapped environment when experimenting with private keys or storing results.

The author accepts no responsibility for misuse, loss, or damage caused by this script.

Limitations & Warnings

Prototype / Untested: The script has not been verified across corner cases. There may be performance, correctness, or stability issues.

The script currently derives only uncompressed public keys and P2PKH addresses (no compressed keys, segwit, or other coins).

SQLite lock handling includes a basic retry/backoff, but concurrency and DB contention can still cause issues.

There is no rate-limiting or safety mechanism preventing accidental generation/storage of extremely large datasets — watch disk space and memory.

Suggested Improvements

Add CLI flags with argparse for flexible configuration.

Support compressed public keys, segwit (Bech32), and other chains (ETH, BCH, SOL, etc.).

Implement configurable concurrency and safe batching for large wordlists.

Add unit tests and integration tests; validate that saved WIFs and private hex match derived addresses.

Add optional encryption for the generated DB or ability to redact private keys when exporting hits.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr

License

Use under a permissive license such as MIT if you want wide reuse, but include the educational/ethical disclaimer and consider adding a RESPONSIBLE_USE.md to the repository.
