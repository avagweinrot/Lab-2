# auth.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: https://docs.python.org/3/library/secrets.html

import hashlib
import os
import hmac
import secrets  
import sqlite3
from datetime import datetime, timezone 
from server.database import get_connection
from server.audit_log import append_entry

# Hash password and salt using PBKDF2 (as we learned in Lab 1), this system will store only the hashed values and salts, not plaintext passwords for security reasons 
def hash_password (password, salt):
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return (hashed)

def register_account (username, password, publicKey):
    username = username.strip().lower()

    if not username and not password:
        return (False, "Username and password required to setup an account.") # Reject blank inputs for either username or password
    
    salt = os.urandom(16)
    hashed_password = hash_password(password, salt)

    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    is_admin = cur.fetchone()[0] == 0 # If a user is the first user in the system, set them to be the admin, that way there is a (theoretically) authorized entity to assign further roles 

    try:
        cur.execute("INSERT INTO users (username, password, salt, publicKey) VALUES (?, ?, ?, ?)", (username, hashed_password, salt, publicKey))
        userID = cur.lastrowid # Pull the automatically assigned user ID for this new user 
        
        if is_admin:
            cur.execute("INSERT INTO roles (userID, role) VALUES (?, ?)", (userID, "admin"))
        
        con.commit()
   
    except sqlite3.IntegrityError:
        return (False, "Username taken.") # No duplicate usernames in the users database 
    
    finally:
        con.close()

    append_entry("User registered", "none") # Log registration event 
    if is_admin:
        append_entry("Role assigned", "system") # Log assignment of the first user as admin if applicable 
    
    return (True, userID)

def login (username, password):
    username = username.strip().lower()

    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT userID, password, salt FROM users WHERE username = ?", (username,))
    user = cur.fetchone() # Pull the user from the users database who has this username 

    if user is None:
        con.close()
        return (False, "Invalid username or password.") # If the username doesn't exist, login fails

    login_input = hash_password(password, user["salt"]) # Hash the inputted password with the stored salt value for that username 
    if not hmac.compare_digest(login_input, user["password"]):
        con.close()
        return (False, "Invalid username or password.") # If the stored hash password doesn't match the computed hash of the input, the password is incorrect and login fails
    
    # Proceed with setting up a session if login is successful
    sessionID = secrets.token_hex(32)
    time = datetime.now(timezone.utc).isoformat()
    cur.execute ("INSERT INTO sessions (sessionID, UserID, time_created) VALUES (?, ?, ?)", (sessionID, user["UserID"], time))
    con.commit()
    con.close()

    append_entry("Login", "user") # Log this login 
    return (True, sessionID)

def logout (sessionID):
    con = get_connection()
    cur = con.cursor()
    
    cur.execute("DELETE FROM sessions WHERE sessionID = ?", (sessionID,)) # Delete the session ID so the session for that user no longer remains active 
    
    con.commit()
    con.close()
    return (True, None)

def get_user (sessionID):
    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT UserID FROM sessions WHERE sessionID = ?", (sessionID,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return None
    return (row["UserID"]) # Return the ID of the user associated with a given session 

def get_role (userID):
    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT role FROM roles WHERE userID = ?", (userID,))
    roles = set()
    for row in cur.fetchall():
        roles.add(row["role"]) # Add every role listed for a given user ID into a single set (compile a user's roles together)
    
    con.close()
    return (roles)

def get_public_key_directory (sessionID):
    if get_user(sessionID) is None:
        return (False, "Unauthorized, not logged in.")
    
    con = get_connection()
    cur = con.cursor()
    
    cur.execute("SELECT UserID, username, publicKey FROM users")
    rows = cur.fetchall()

    con.close()
    return (True, rows) # Return the public key of every user in the system to avoid having to request the server for a specific public key, which would notify the server of the intended recipient and defeat anonymity 
