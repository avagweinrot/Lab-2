# messages.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: 

import sqlite3
from datetime import datetime, timezone 
from server.database import get_connection
from server.auth import get_role
from server.rbac import require_permission
from server.tokens import check_token
from server.audit_log import append_entry

def timestamp():
    return datetime.now(timezone.utc).isoformat() # Return current date and time, needed for knowing when messages are sent and flagged  

def send_message (receipient_username, ciphertext, encryptedKey, nonce, token):
    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT userID FROM users WHERE username = ?", (receipient_username.strip().lower(), ))
    row = cur.fetchone()
    if row is None:
        con.close()
        return (False, "Recipient does not exist.")
    
    recipientID = row["userID"] # Pull the ID of the intended recipient from their row in the users table 
    
    if "recipient" not in get_role(recipientID):
        con.close()
        return (False, "This user is not authorized to recieve messages")
    
    # Check to see if the token is valid to send a message 
    ok, reason = check_token(cur, token)
    if not ok:
        con.close()
        append_entry("Message attempt rejected", "sender") # Log attempt at either reusing or using a fake/invalid token 
        return (False, reason)
    
    # Add the message being sent to the messages table 
    cur.execute("INSERT INTO messages (recipientID, ciphertext, encryptedKey, nonce, value, created) "  "VALUES (?, ?, ?, ?, ?, ?)", 
    (recipientID, ciphertext, encryptedKey, nonce, token, timestamp())) 

    cur.execute("UPDATE tokens SET used = 1 WHERE value = ?", (token, )) # Update token in the table to be marked as spent 
    con.commit()
    con.close() 

    append_entry ("Message sent", "sender")
    return (True, "Message sent.")

def get_inbox (sessionID):
    # Only recipients can view an inbox to read messages
    ok, result = require_permission(sessionID, "view_inbox")
    if not ok:
        return (False, result)
    userID, role = result

    con = get_connection()
    cur = con.cursor()

    # Get the messages associated with the recipieint's user ID 
    cur.execute("SELECT messageID, ciphertext, encryptedKey, nonce, created FROM messages WHERE recipientID = ?", (userID, ))
    rows = cur.fetchall() # Retrieve the user's entire "inbox," this will be encrypted with the recipient's public key but the recipient will decrypt with their private key
    con.close()

    append_entry("Inbox opened", "recipient") # Log the opening of the inbox by a recipient 
    return (True, rows)

def flag_message (sessionID, messageID, reason, plaintext):
    # Recipients are the only users capable of flagging messages 
    ok, result = require_permission(sessionID, "flag_message")
    if not ok:
        return (False, result)
    userID, role = result

    con = get_connection()
    cur = con.cursor()

    cur.execute("SELECT recipientID, flagged FROM messages WHERE messageID = ?", (messageID, ))
    row = cur.fetchone()
    
    # Check if the user attempting to flag a message and the recipient of the message are the same 
    if row is None or row["recipientID"] != userID:
        con.close()
        return (False, "Users may only flag messages they have received.")
    
    if row["flagged"]:
        con.close()
        return (False, "Message has already been flagged.")
    
    # Add the flagged message to the flagged table and update the message in the messages table to be marked as flagged 
    cur.execute ("INSERT INTO flags (messageID, reason, plaintext, created) VALUES (?, ?, ?, ?)", (messageID, reason, plaintext, timestamp()))
    cur.execute ("UPDATE messages SET flagged = 1 WHERE messageID = ?", (messageID, ))
    con.commit()
    con.close()

    append_entry ("Message flagged", "recipient")
    return (True, "Message flagged successfully.")

def view_flagged (sessionID):
    # Only moderators can view flagged messages 
    ok, result = require_permission(sessionID, "view_flagged")
    if not ok:
        return (False, result)
    
    con = get_connection()
    cur = con.cursor()

    cur.execute ("SELECT flagID, messageID, reason, plaintext, created FROM flags WHERE status = 'open'")
    rows = cur.fetchall() # Moderators can view the list of flagged messages 
    con.close()

    return (True, rows)

def freeze_token (sessionID, flagID, reason):
    # Only moderators can freeze tokens 
    ok, result = require_permission(sessionID, "freeze_token")
    if not ok:
        return (False, result)

    con = get_connection()
    cur = con.cursor()

    # Get the token associated with a flagged message using the flag ID 
    cur.execute("SELECT messages.value FROM flags JOIN messages ON flags.messageID = messages.messageID " "WHERE flags.flagID = ? AND flags.status = 'open'", (flagID, ))
    row = cur.fetchone()
    if row is None:
        con.close()
        return (False, "There is no flagged message with that ID.")
    
    try:
        cur.execute ("INSERT INTO frozen (value, reason, time) VALUES (?, ?, ?)", (row["value"], reason, timestamp())) # Add this token to the table of frozen tokens 
        cur.execute ("UPDATE flags SET status = 'resolved' WHERE flagID = ?", (flagID, )) # Update this flagged mesasge in the flagged table to show that proper action has been taken (the token associated with the message has been frozen)
        con.commit()
    
    except sqlite3.IntegrityError:
        return (False, "This token is already frozen.")
    
    finally:
        con.close() 
    
    append_entry ("Token frozen", "moderator")
    return (True, "Token has been frozen successfully.")

