# database.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: https://www.youtube.com/watch?v=P5rlLlztkNs, https://stackoverflow.com/questions/576933/how-can-i-reference-columns-by-their-names-in-python-calling-sqlite  

import sqlite3
from pathlib import Path 

db_name = "whisperchain.db"
root_folder = Path(__file__).resolve().parent.parent # Get the root folder location of where this database file sits on the machine for proper running and creation 
db_path = root_folder / db_name
log_key_path = root_folder / "server" / "keys" / "log.key"

ROLES = {"sender", "recipient", "moderator", "admin"}

def get_connection():
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON") # We want to be able to look up columns by their name and not just by position 
    return con 

# Initialize a table with username and password credentials for each service
def create_table():
    con = get_connection()
    cur = con.cursor()

    # Register users and public keys
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            userID INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            salt TEXT NOT NULL,
            publicKey BLOB NOT NULL
        )
    """)

    # User roles in the system
    cur.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            userID INTEGER NOT NULL REFERENCES users(userID),
            role TEXT NOT NULL,
            UNIQUE (userID, role)
        )
    """)

    # Active login sessions
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            sessionID TEXT PRIMARY KEY,
            userID INTEGER NOT NULL REFERENCES users (userID),
            time_created TEXT NOT NULL
        )
    """)

    # Sending rounds
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rounds (
            roundNum INTEGER PRIMARY KEY,
            active INTEGER NOT NULL DEFAULT 0,
            start TEXT,
            end TEXT
        )
    """)

    # Records of users receiving tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens_issued (
            userID INTEGER NOT NULL REFERENCES users(userID),
            roundNum INTEGER NOT NULL REFERENCES rounds(roundNum),
            UNIQUE (userID, roundNum)
        )
    """)

    # Valid tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            value TEXT PRIMARY KEY,
            roundNum INTEGER NOT NULL REFERENCES rounds(roundNum),
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Encrypted messages 
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            messageID INTEGER PRIMARY KEY,
            receipientID INTEGER NOT NULL REFERENCES users(userID),
            ciphertext BLOB NOT NULL,
            encryptedKey BLOB NOT NULL,
            nonce BLOB NOT NULL,
            value TEXT NOT NULL REFERENCES tokens(token),
            created TEXT NOT NULL,
            flagged INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Flagged message reports 
    cur.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            flagID INTEGER PRIMARY KEY,
            messageID INTEGER NOT NULL REFERENCES messages(messageID),
            reason TEXT,
            plaintext TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            created TEXT NOT NULL
        )
    """)

    # Frozen tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS frozen (
            value TEXT PRIMARY KEY REFERENCES tokens(token),
            reason TEXT,
            frozen TEXT NOT NULL
        )
    """)

    # Audit log 
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            sequence INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            role TEXT NOT NULL,
            previousHash TEXT NOT NULL,
            entryHash TEXT NOT NULL,
            signature TEXT NOT NULL
        )
    """)

    con.commit()
    con.close()

# FOR TESTING, CREATE TABLES 
if __name__ == "__main__":
    create_table()

