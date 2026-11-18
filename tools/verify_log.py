# verify_log.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions

import sys
import hmac
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.audit_log import INITIAL_HASH, compute_hash, compute_hmac, get_entries
from server.database import log_key_path

def main():
	# Check if log key exists and raise error if it doesn't
	if not log_key_path.exists():
		print("Error: no log key found.")
		sys.exit(2)

	# Get rows from audit log
	rows = get_entries()

	# Start at the beginning of the log
	correct_previous_hash = INITIAL_HASH
	correct_sequence = 1

	# Loop through log rows to check each entry for tampering
	for row in rows:
		# Check order and previous hashes to identify gaps or breaks in the chain
		if row["sequence"] != correct_sequence or row["previousHash"] != correct_previous_hash:
			print(f"Gap found in log entries at entry {row['sequence']}.")
			sys.exit(1)

		# Recompute and check hashes to ensure that they match what is expected
		recomputed_hash = compute_hash(row["sequence"], row["timestamp"], row["action"], row["role"], row["previousHash"])
		if not hmac.compare_digest(recomputed_hash,row["entryHash"]):
			print(f"Contents were edited at entry {row['sequence']}.")
			sys.exit(1)

		# Recompute and check hmac singature to identify tampering if applicable
		recomputed_hmac = compute_hmac(row["entryHash"])
		if not hmac.compare_digest(recomputed_hmac, row["signature"]):
			print(f"Signature is invalid at entry {row['sequence']}.")
			sys.exit(1)

		# Move seqeuence and previous hash forward in log
		correct_previous_hash = row["entryHash"]
		correct_sequence = row["sequence"] + 1

	# Confirm log verification and exit successfully
	print("Log verified for all entries. No tampering detected.")
	sys.exit(0)
		
if __name__ == "__main__":
	main()

