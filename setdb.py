from cs50 import SQL

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///wish.db")

db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTO INCREMENT")