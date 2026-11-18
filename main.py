# main.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: none

from server.database import create_table
from client.cli import run

# Initializes database and interactive menu
if __name__ == "__main__":
	create_table()
	run()