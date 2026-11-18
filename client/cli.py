# cli.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: 

import getpass
from client import crypto_utils
from server.auth import register_account, login, logout, get_user, get_role, get_public_key_directory
from server.rbac import assign_role, remove_role, view_log
from server.tokens import start_round, end_round, request_token, get_active_round
from server.messages import send_message, get_inbox, flag_message, view_flagged, freeze_token

def run():
	session = None
	username = None
	private_key = None 
	token = None
	decrypted = {}

	print("Hello. Welcome to WhisperChain+.")

	# Outer loop represents the state when the user is not logged in yet
	while True:
		action = input("0) Exit \n1) Register \n2) Login\n").strip()

		# EXIT
		if action == "0":
			break

		# REGISTER
		elif action == "1":
			username = input("Enter username: ").strip().lower()
			password = getpass.getpass("Enter password: ")

			# Generate the key pair on the client so that the server never sees the private key
			new_private, new_public = crypto_utils.generate_key_pair()
			ok, result = register_account(username, password, crypto_utils.serialize_public_key(new_public))

			# Only save the private key if registration worked
			if ok:
				crypto_utils.save_private_key(new_private, username, password)
				print("Registration successful. An admin must assign you a role.")
			else:
				print(result)

		# LOGIN
		elif action == "2":
			username = input("Enter username: ").strip().lower()
			password = getpass.getpass("Enter password: ")

			ok, result = login(username, password)
			if not ok:
				print(result)
				continue

			session = result

			try:
				private_key = crypto_utils.load_private_key(username, password)
			except ValueError:
				private_key = None
			if private_key is None:
				print("No private key found.")

			print(f"Logged in as {username}.")

			# Inner loop represents the state where the user is logged in, menu depends on their roles
			while True:
				roles = get_role(get_user(session))

				# Only shows the options this user's roles allow (the server still enforces permissions on every call)
				menu = ""
				if "sender" in roles:
					menu += "1) Request token \n2) Send message \n"
				if "recipient" in roles:
					menu += "3) Open inbox \n4) Flag message \n"
				if "moderator" in roles:
					menu += "5) View flagged messages \n6) Freeze token \n7) View audit log \n"
				if "admin" in roles:
					menu += "8) Assign role \n9) Remove role \n10) Start round \n11) End round \n"
				menu += "0) Logout \n"

				goal = input(menu).strip()

				# REQUEST TOKEN
				if goal == "1" and "sender" in roles:
					ok, result = request_token(session)
					if ok:
						token = result
						print("Token issued for this round.")
					else:
						print(result)

				# SEND MESSAGE
				elif goal == "2" and "sender" in roles:
					if token is None:
						print("Request a token first.")
						continue

					# Get every user's public key, so the server can't tell who we're about to message
					ok, directory = get_public_key_directory(session)
					if not ok:
						print(directory)
						continue
					keys = {row["username"]: row["publicKey"] for row in directory}

					recipient = input("Enter recipient username: ").strip().lower()
					if recipient not in keys:
						print("No user with that username.")
						continue
					text = input("Enter your anonymous message: ")

					# Encrypt on the client before anything is sent to the server
					ciphertext, encrypted_key, nonce = crypto_utils.encrypt_message(keys[recipient], text)
					ok, result = send_message(recipient, ciphertext, encrypted_key, nonce, token)
					print(result)
					if ok:
						token = None

				# OPEN INBOX
				elif goal == "3" and "recipient" in roles:
					ok, rows = get_inbox(session)
					if not ok:
						print(rows)
						continue
					if not rows:
						print("Inbox is empty.")
					if rows and private_key is None:
						print("No private key loaded, can't decrypt messages.")
						continue

					# Decrypt each message locally with the recipient's private key
					for row in rows:
						try:
							text = crypto_utils.decrypt_message(private_key, row["ciphertext"], row["encryptedKey"], row["nonce"])
							decrypted[row["messageID"]] = text
						except Exception:
							text = "[could not decrypt, message may have been tampered with]"
						print(f"#{row['messageID']} ({row['created'][:16]}): {text}")

				# FLAG MESSAGE
				elif goal == "4" and "recipient" in roles:
					try:
						message_id = int(input("Enter message number to flag: "))
					except ValueError:
						print("Please enter a number.")
						continue
					if message_id not in decrypted:
						print("Open your inbox first, then choose a message from it.")
						continue

					# Flagging is the only way message text reaches the server, and it's the recipient's choice
					reason = input("Enter reason: ")
					ok, result = flag_message(session, message_id, reason, decrypted[message_id])
					print(result)

				# VIEW FLAGGED MESSAGES
				elif goal == "5" and "moderator" in roles:
					ok, rows = view_flagged(session)
					if not ok:
						print(rows)
						continue
					if not rows:
						print("No open flags.")
					for row in rows:
						print(f"Flag #{row['flagID']} (message #{row['messageID']}) reason: {row['reason']}")
						print(f"    \"{row['plaintext']}\"")

				# FREEZE TOKEN
				elif goal == "6" and "moderator" in roles:
					try:
						flag_id = int(input("Enter flag number: "))
					except ValueError:
						print("Please enter a number.")
						continue
					reason = input("Enter reason: ")
					ok, result = freeze_token(session, flag_id, reason)
					print(result)

				# VIEW AUDIT LOG
				elif goal == "7" and "moderator" in roles:
					ok, rows = view_log(session)
					if not ok:
						print(rows)
						continue
					for row in rows:
						print(f"{row['sequence']}  {row['timestamp'][:19]}  {row['role']}  {row['action']}")

				# ASSIGN ROLE
				elif goal == "8" and "admin" in roles:
					target = input("Enter username: ")
					role = input("Enter role (sender, recipient, moderator, admin): ")
					ok, result = assign_role(session, target, role)
					print(result)

				# REMOVE ROLE
				elif goal == "9" and "admin" in roles:
					target = input("Enter username: ")
					role = input("Enter role to remove: ")
					ok, result = remove_role(session, target, role)
					print(result)

				# START ROUND
				elif goal == "10" and "admin" in roles:
					ok, result = start_round(session)
					if ok:
						print(f"Round {result} started.")
					else:
						print(result)

				# END ROUND
				elif goal == "11" and "admin" in roles:
					ok, result = end_round(session)
					print(result)

				# LOGOUT
				elif goal == "0":
					logout(session)
					session = None
					private_key = None
					token = None
					decrypted = {}
					print("Logged out.")
					break

				else:
					print("Invalid input.")

		else:
			print("Invalid input.")

	# End of session
	print("Session ended. Goodbye.")