# tokens.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: https://dev.to/serhatteker/how-to-create-secret-tokens-in-python-3nll

import sqlite3
import secrets 
from datetime import datetime, timezone
from server.database import get_connection
from server.audit_log import append_entry
from server.rbac import require_permission

def timestamp():
    return datetime.now(timezone.utc).isoformat() # Return current date and time, needed for knowing when rounds start and end 

def get_active_round():
    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT roundNum FROM rounds WHERE active = 1")
    row = cur.fetchone()
    con.close()

    if row is None:
        return (None)
    
    return (row["roundNum"])

def start_round (sessionID):
    ok, result = require_permission (sessionID, "start_round")   
    if not ok:
        return (False, result)
    
    con = get_connection()
    cur = con.cursor()

    cur.execute("UPDATE rounds SET active = 0, end = ? WHERE active = 1", (timestamp(), )) # Close existing rounds so only one is ever open
    cur.execute("SELECT MAX (roundNum) FROM rounds ")  
    highestNum = cur.fetchone()[0]
    new_round = 0
    if highestNum is None:
        new_round = 1
    else:
        new_round = highestNum + 1
    
    cur.execute("INSERT INTO rounds (roundNum, active, start) VALUES (?, 1, ?)", (new_round, timestamp())) # Add this new active round to the table
    con.commit()
    con.close()

    append_entry ("Start round", "admin") # Log the starting of a round 
    return (True, new_round)

def end_round(sessionID):
    ok, result = require_permission (sessionID, "manage_rounds")   
    if not ok:
        return (False, result)
    
    current = get_active_round()
    if current is None:
        return (False, "No active rounds.")
    
    con = get_connection()
    cur = con.cursor()

    cur.execute("UPDATE rounds SET active = 0, end = ? WHERE roundNum = ?", (timestamp(), current)) # Set the current round to inactive, with the current timestamp 
    con.commit()
    con.close()

    append_entry("End round", "admin") # Log the ending of a round 
    return (True, "Round ended.")

def request_token(sessionID):
    ok, result = require_permission (sessionID, "request_token")   
    if not ok:
        return (False, result)
    userID, role = result # Get the ID and role of the user requesting this action (will be senders)

    current = get_active_round()
    if current is None:
        return (False, "No active rounds.")
    
    token = secrets.token_urlsafe(32) # Function returns a random URL-safe text string containing 32 bytes 

    con = get_connection()
    cur = con.cursor()

    try:
        cur.execute("INSERT INTO tokens_issued (userID, roundNum) VALUES (?, ?)", (userID, current)) # Add to table that this user was issued a token this round
        cur.execute("INSERT INTO tokens (value, roundNum) VALUES (?, ?)", (token, current)) # Add the actual token itself to the table 
        con.commit()
    
    except sqlite3.IntegrityError:
        return (False, "Token already issued for this round.")
    
    finally:
        con.close()
    
    append_entry("Token requested and issued", "sender")
    return (True, token)

def check_token(cur, token):
    cur.execute("SELECT roundNum, used FROM tokens WHERE value = ?", (token,)) # This method is used by send_message, so it relies on the connection opened there and the associated cursor 
    row = cur.fetchone()
    
    # Perform series of checks on token 
    if row is None:
        return (False, "Invalid token.")
    if row["roundNum"] != get_active_round():
        return (False, "Token is not valid for this round.")
    if row["used"]:
        return (False, "This token has aleady been used")
    
    # Check to see if this token has been previously frozen by a moderator 
    cur.execute("SELECT 1 FROM frozen WHERE value = ?", (token, ))
    if cur.fetchone() is not None:
        return (False, "This is a frozen token.")
    
    return (True, "Token is valid.")

# TEST FOR DEBUGGING 
if __name__ == "__main__":
    from server.database import create_table
    from server.auth import register_account, login
    from server.rbac import assign_role
    create_table()

    register_account("admin", "adminpass", b"k1")
    register_account("alice", "alicepass", b"k2")
    _, admin_s = login("admin", "adminpass")
    _, alice_s = login("alice", "alicepass")
    assign_role(admin_s, "alice", "sender")

    print(request_token(alice_s))              # no active round
    print(start_round(alice_s))                # denied: not admin
    print(start_round(admin_s))                # (True, 1)
    ok, token = request_token(alice_s)
    print(ok, token[:10] + "...")              # True + start of token
    print(request_token(alice_s))              # already issued this round
    print(request_token(admin_s))              # denied: admin isn't a sender

    con = get_connection()
    cur = con.cursor()
    print(check_token(cur, token))             # valid
    print(check_token(cur, "made-up-token"))   # invalid
    cur.execute("UPDATE tokens SET used = 1 WHERE value = ?", (token,))
    con.commit()
    print(check_token(cur, token))             # already used
    con.close()

    print(start_round(admin_s))                # (True, 2)
    ok, token2 = request_token(alice_s)
    print("new round token:", ok)              # True: new round, new token

    con = get_connection()
    cur = con.cursor()
    print(check_token(cur, token))             # old round's token rejected
    con.close()

    print(end_round(admin_s))                  # ended
    print(end_round(admin_s))                  # no active round
    con = get_connection()
    cur = con.cursor()
    print(check_token(cur, token2))            # rejected: no round is active
    con.close()

    


