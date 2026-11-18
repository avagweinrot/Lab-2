# rbac.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions

import sqlite3
from server.database import get_connection
from server.audit_log import append_entry, get_entries
from server.auth import get_user, get_role

ROLES = {"sender", "recipient", "moderator", "admin"}

PERMISSIONS = {"log_in": {"sender", "recipient", "admin", "moderator"}, "request_token": {"sender"}, "send_message": {"sender"},
"view_inbox":    {"recipient"},  "flag_message":  {"recipient"}, "view_flagged":  {"moderator"}, "freeze_token":  {"moderator"},
"assign_role":   {"admin"}, "remove_role": {"admin"}, "start_round": {"admin"}, "manage_rounds": {"admin"}, "view_log": {"moderator"}, "change_keys": {"admin"}}

CONFLICTS = {"admin", "moderator"} # Admin should not be allowed to see message content, but moderators can see flagged content

def require_permission (sessionID, permission):
    userID = get_user(sessionID)
    if userID is None:
        return (False, "Not logged in.")
    
    roles = get_role(userID)
    allowed = PERMISSIONS[permission]
    matching = roles & allowed

    if not matching:
        append_entry("Access denied", "User")
        return (False, "Permission denied.")
    
    return (True, (userID, next(iter(matching)))) # Return the user ID as well as the associated role that allowed for the user to have permission to perform a requested action

def assign_role (sessionID, username, role):
    # Enforce the role-based access control model for function that should be protected (only Admin can assign roles)
    ok, result = require_permission (sessionID, "assign_role")   
    if not ok:
        return (False, result)
    
    role = role.strip().lower()
    if role not in ROLES:
        return (False, "Invalid role.")
    
    con = get_connection()
    cur = con.cursor()

    # Retrieve the target userID for the given username 
    cur.execute("SELECT userID FROM users WHERE username = ?", (username.strip().lower(),))
    row = cur.fetchone() # Get the user ID associated with the username 
    if row is None:
        con.close()
        return (False, "User does not exist in the system.")
    ID = row["userID"]
    
    # Check for appropriate separation of duties 
    current_role = get_role(ID)
    if role in CONFLICTS and (current_role & CONFLICTS) - {role}:
        con.close()
        return (False, "User cannot be Admin and Moderator.")
    
    try:
        cur.execute("INSERT INTO roles (userID, role) VALUES (?, ?)", (ID, role))
        con.commit()
    
    except sqlite3.IntegrityError:
        return (False, "Role already assigned to user.")
    
    finally:
        con.close()
    
    append_entry("Role assigned", "admin") # Log the assigning of a role 
    return (True, "Role assigned successfully.")

def remove_role (sessionID, username, role):
    # Enforce the role-based access control model for function that should be protected (only Admin can modify roles)
    ok, result = require_permission (sessionID, "remove_role")   
    if not ok:
        return (False, result)
    
    role = role.strip().lower()

    con = get_connection()
    cur = con.cursor()

    # Retrieve the target userID for the given username 
    cur.execute("SELECT userID FROM users WHERE username = ?", (username.strip().lower(),))
    row = cur.fetchone() # Get the user ID associated with the username 
    if row is None:
        con.close()
        return (False, "User does not exist in the system.")
    ID = row["userID"]

    cur.execute("DELETE FROM roles WHERE userID = ? AND role = ?", (ID, role))
    removed = cur.rowcount # Retrieving this count allows us to verify whether anything was actually removed (will be 0 if user never had the role the Admin is trying to remove)
    con.commit()
    con.close()

    if removed == 0:
        append_entry ("Removal attempt, but unsuccessful", "admin")
        return (False, "Remove unsuccessful because user not assigned that role.")
    
    append_entry ("Role removed", "admin") # Log confirmed removal 
    return (True, "Removal successful.")

def view_log (sessionID):
     # Enforce the role-based access control model for function that should be protected (only Admin can modify roles)
    ok, result = require_permission (sessionID, "view_log")   
    if not ok:
        return (False, result)
    
    return (True, get_entries())