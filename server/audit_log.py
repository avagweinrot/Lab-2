# audit_log.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: https://www.okta.com/identity-101/hmac/ 

import hashlib
import os
import hmac
from server.database import log_key_path, get_connection, create_table 
from datetime import datetime, timezone 

INITIAL_HASH = "0" * 64 # The "previous hash" for the log's first entry

def get_log_key():
    if log_key_path.exists():
        with open(log_key_path, "rb") as key_file:
            return key_file.read()
    
    log_key_path.parent.mkdir(parents = True, exist_ok = True) #Creates folder to store key file if it doesn't already exist 
    key = os.urandom(32)

    # Create the log key if doesn't already exist and add to fle 
    with open (log_key_path, "wb") as key_file:
        key_file.write(key)
    return (key) 

def compute_hash(sequence, timestamp, action, role, previousHash):
    text = "|".join([str(sequence), timestamp, action, role, previousHash]) # Include the previous hash so a hash chain is created in the audit log, linking entries 
    hash = hashlib.sha256(text.encode()).hexdigest() # Utilize SHA256 hash algorithm, then convert the hash to readable text 
    return (hash)

def compute_hmac(entryHash):
    key = get_log_key()
    value = hmac.new(key, entryHash.encode(), hashlib.sha256).hexdigest() # Combine hash with the generated private log key to reduce tamperability 
    return (value)

def append_entry(action, role):
    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT sequence, entryHash FROM audit_log ORDER BY sequence DESC LIMIT 1") # Orders the log newest to oldest, and takes one row 
    recent = cur.fetchone() # Pull this most recent row 

    if recent is None:
        sequence = 1
        previousHash = INITIAL_HASH # If this is the first log entry, begin with the initial all-zero hash 
    else:
        sequence = recent["sequence"] + 1
        previousHash = recent["entryHash"] # Otherwise continue advancing the hash chain as the log grows 
    
    timestamp = datetime.now(timezone.utc).isoformat() # Using the world's universal standard time 
    entryHash = compute_hash(sequence, timestamp, action, role, previousHash) # Compute the hash for this entry (based on entry number, time, action, role of executor, previous hash)
    signature = compute_hmac(entryHash) # "Sign" the entry by adding the private key to the entry hash 

    # Actually add the new entry to the log 
    cur.execute("INSERT INTO audit_log (sequence, timestamp, action, role, previoushash, entryHash, signature)" 
     "VALUES (?, ?, ?, ?, ?, ?, ?)", (sequence, timestamp, action, role, previousHash, entryHash, signature))
    con.commit()
    con.close()

def get_entries():
    con = get_connection()
    cur = con.cursor()
    cur.execute("SELECT * from audit_log ORDER BY sequence")
    rows = cur.fetchall()
    con.close()
    return (rows) # Returns all log entries ordered from oldest to newest 
