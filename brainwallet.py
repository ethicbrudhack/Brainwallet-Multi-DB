#!/usr/bin/env python3
"""
brainwallet_multi_db.py – klasyczny brainwallet + warianty na frazę
Dla każdej frazy generuje VARIANTS unikalnych adresów:
 - wariant 0 = klasyczny brainwallet (SHA256(passphrase))
 - wariant 1..N = SHA256(passphrase + str(index))
Zapisuje WSZYSTKIE wygenerowane adresy i klucze do SQLite (generated_addresses.db domyślnie)
Sprawdza trafienia w bazie SQLite (tabela addresses.address) jeśli podana.
"""
import sys
import os
import time
import hashlib
import sqlite3
from ecdsa import SigningKey, SECP256k1

# --- Ustawienia ---
DB_PATH_DEFAULT = "alladdresses.db"           # baza do sprawdzania (read-only)
GEN_DB_DEFAULT = "generated_addresses2.db"      # baza do zapisywania wygenerowanych rekordów
FOUND_FILENAME = "znalazlembrainwallet1.txt"    # plik z trafieniami
DB_RETRIES = 5
DB_BACKOFF_BASE = 0.2
DB_TIMEOUT = 5
VARIANTS = 100   # ile adresów z jednej frazy (ustawione na 30)
PROGRESS_INTERVAL = 100

CURVE = SECP256k1

# --- Funkcje kryptograficzne ---
def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def private_key_from_phrase_variant(phrase: str, index: int) -> bytes:
    """Wariant 0 = klasyczny brainwallet (SHA256(passphrase)).
       Pozostałe warianty = SHA256(passphrase + str(index))."""
    # jeśli w wordlist_bez_duplikatow.txt wpiszesz "<EMPTY>", traktujemy to jako pustą frazę
    if phrase == "<EMPTY>":
        phrase = ""
    if index == 0:
        return hashlib.sha256(phrase.encode("utf-8")).digest()
    else:
        return hashlib.sha256((phrase + str(index)).encode("utf-8")).digest()


def pubkey_uncompressed_from_priv(priv_bytes: bytes) -> bytes:
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    xy = vk.to_string()
    return b'\x04' + xy

def p2pkh_address_from_pubkey(pubkey_bytes: bytes) -> str:
    sha = hashlib.sha256(pubkey_bytes).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    payload = b"\x00" + rip
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    import base58
    return base58.b58encode(payload + checksum).decode("utf-8")

def wif_from_priv(priv_bytes: bytes) -> str:
    # klasyczny WIF dla niekompresowanego klucza (prefix 0x80, bez 0x01 na końcu)
    prefix = b"\x80" + priv_bytes
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    import base58
    return base58.b58encode(prefix + checksum).decode("utf-8")

# --- Funkcje DB (check DB) ---
def address_exists_in_db(conn: sqlite3.Connection, address: str, attempt_prefix: str = "") -> bool:
    attempt = 0
    while True:
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM addresses WHERE address = ? LIMIT 1", (address,))
            return cur.fetchone() is not None
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            stamp = time.strftime("%H:%M:%S")
            if "locked" in msg:
                if attempt < DB_RETRIES:
                    backoff = DB_BACKOFF_BASE * (2 ** attempt)
                    print(f"[⚠️ {stamp}] {attempt_prefix}Baza zablokowana, czekam {backoff:.2f}s")
                    time.sleep(backoff)
                    attempt += 1
                    continue
                else:
                    print(f"[❌] {attempt_prefix}Baza nadal zablokowana — pomijam")
                    return False
            else:
                print(f"[❌] {attempt_prefix}Błąd SQLite: {exc}")
                return False
        except Exception as exc:
            print(f"[❌] {attempt_prefix}Inny błąd: {exc}")
            return False

# --- Funkcje DB (generated DB) ---
def init_generated_db(gen_db_path: str) -> sqlite3.Connection:
    """Tworzy (jeśli potrzebne) bazę do zapisu wygenerowanych rekordów i zwraca połączenie."""
    need_create = not os.path.isfile(gen_db_path)
    conn = sqlite3.connect(gen_db_path, timeout=DB_TIMEOUT, check_same_thread=False)
    cur = conn.cursor()
    # tabela generated: id, line, variant, passphrase, address, wif, priv_hex, created_at
    cur.execute("""
    CREATE TABLE IF NOT EXISTS generated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        line INTEGER,
        variant INTEGER,
        passphrase TEXT,
        address TEXT,
        wif TEXT,
        priv_hex TEXT,
        created_at TEXT
    )
    """)
    # indeks na address przyspieszy ewentualne zapytania
    cur.execute("CREATE INDEX IF NOT EXISTS idx_generated_address ON generated(address)")
    conn.commit()
    return conn

def insert_generated_record(conn: sqlite3.Connection, record: dict):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO generated (line, variant, passphrase, address, wif, priv_hex, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (record["line"], record["variant"], record["passphrase"], record["address"], record["wif"], record["priv_hex"], record["created_at"])
    )
    # nie commitujemy tutaj za każdym razem (batched commit będzie lepszy). Commity robimy co N lub na końcu.

# --- Główna funkcja ---
def process_file(input_path: str, output_csv: str, check_db_path: str = DB_PATH_DEFAULT, gen_db_path: str = GEN_DB_DEFAULT):
    if not os.path.isfile(input_path):
        print(f"Brak pliku wejściowego: {input_path}")
        return

    # Połączenie z DB do sprawdzania (read-only) jeśli istnieje
    check_conn = None
    if os.path.isfile(check_db_path):
        try:
            db_uri = f"file:{check_db_path}?mode=ro"
            check_conn = sqlite3.connect(db_uri, uri=True, timeout=DB_TIMEOUT, check_same_thread=False)
            print(f"[DB] Połączono z {check_db_path} (do sprawdzania)")
        except Exception as e:
            print(f"[DB] Nie udało się połączyć do sprawdzania: {e}")
            check_conn = None
    else:
        print(f"[DB] Brak bazy {check_db_path} – pomijam sprawdzanie")

    # Połączenie z DB do zapisu wygenerowanych rekordów
    gen_conn = init_generated_db(gen_db_path)
    gen_cur = gen_conn.cursor()

    total_generated = 0
    hits = 0
    results = []
    pending_inserts = 0
    BATCH_COMMIT = 500  # commit co N insertów

    with open(input_path, "r", encoding="utf-8") as infile, \
         open(FOUND_FILENAME, "a", encoding="utf-8") as foundf:

        for lineno, raw in enumerate(infile, start=1):
            phrase = raw.strip() 
            if not phrase:
                continue 

            for i in range(VARIANTS):
                try:
                    priv = private_key_from_phrase_variant(phrase, i)
                    pub = pubkey_uncompressed_from_priv(priv)
                    addr = p2pkh_address_from_pubkey(pub)
                    wif = wif_from_priv(priv)
                    total_generated += 1

                    record = {
                        "line": lineno,
                        "variant": i,
                        "passphrase": phrase,
                        "address": addr,
                        "wif": wif,
                        "priv_hex": priv.hex(),
                        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                    }

                    # Zapis do bazy generated
                    insert_generated_record(gen_conn, record)
                    pending_inserts += 1

                    # commit batchowo
                    if pending_inserts >= BATCH_COMMIT:
                        gen_conn.commit()
                        pending_inserts = 0

                    # sprawdź w DB (jeśli podłączone)
                    if check_conn and address_exists_in_db(check_conn, addr, f"[Line {lineno}] "):
                        foundf.write(f"{addr},{wif},{phrase},{i},{priv.hex()}\n")
                        hits += 1
                        print(f"[💥 HIT] {phrase!r} #{i} -> {addr}")

                    # pokazuj postęp
                    if total_generated % PROGRESS_INTERVAL == 0:
                        print(f"[⏳] Wygenerowano {total_generated} adresów...", flush=True)

                    results.append({
                        "line": lineno,
                        "variant": i,
                        "passphrase": phrase,
                        "address": addr,
                        "wif": wif,
                        "priv_hex": priv.hex()
                    })

                except Exception as e:
                    print(f"[❌] Błąd przy {phrase}#{i}: {e}")

    # commit pozostałych insertów
    if pending_inserts > 0:
        gen_conn.commit()

    if check_conn:
        check_conn.close()
    if gen_conn:
        gen_conn.close()

    # zapis CSV (opcjonalny, jeśli chcesz mieć CSV wyników)
    with open(output_csv, "w", newline='', encoding="utf-8") as csvf:
        import csv
        fields = ["line", "variant", "passphrase", "address", "wif", "priv_hex"]
        writer = csv.DictWriter(csvf, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[✅] Zakończono.")
    print(f"Wygenerowano {total_generated} adresów (z {len(results)} rekordów)")
    print(f"Trafienia w DB: {hits}")
    print(f"Baza wygenerowanych: {gen_db_path} (tabela 'generated')")
    print(f"Trafienia: {FOUND_FILENAME}")
    print(f"Wyniki CSV: {output_csv}")

# --- Uruchomienie ---
if __name__ == "__main__":
    args = sys.argv[1:]
    in_path = args[0] if len(args) >= 1 else "slowadobrainwallet.txt"
    out_path = args[1] if len(args) >= 2 else "result1s.csv"
    check_db = args[2] if len(args) >= 3 else DB_PATH_DEFAULT
    gen_db = args[3] if len(args) >= 4 else GEN_DB_DEFAULT
    process_file(in_path, out_path, check_db, gen_db)
