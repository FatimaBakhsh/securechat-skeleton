"""
Module responsible for preparing and managing the application's MySQL storage layer.

Functions:
- Loads DB configuration from environment variables.
- Creates the database and essential tables.
- Can be executed directly using: `python -m app.storage.db --init`
"""

import os
import sys
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import errorcode

load_dotenv()   # Fetch variables from .env

# Collect DB credentials from environment
HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
PORT = os.getenv("MYSQL_PORT", "3306")
USER = os.getenv("MYSQL_USER")
PASSWORD = os.getenv("MYSQL_PASSWORD")
DATABASE = os.getenv("MYSQL_DATABASE")

# Ensure required environment variables are present
if not all([HOST, PORT, USER, PASSWORD, DATABASE]):
    print("Missing required MySQL credentials. Verify your .env file.")
    sys.exit(1)


# Structure for storing user login information (salted hash system)
USER_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
"""

def setup_database():
    """
    Connects to MySQL, ensures the database exists, and creates required tables.
    """
    connection = None
    cursor = None

    try:
        # First connect without selecting a database
        connection = mysql.connector.connect(
            host=HOST,
            port=PORT,
            user=USER,
            password=PASSWORD
        )

        cursor = connection.cursor()

        # Create DB if needed
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE}")
        print(f"Database '{DATABASE}' is ready.")

        # Select the database
        connection.database = DATABASE

        # Create user table
        cursor.execute(USER_TABLE_SCHEMA)
        print("Table 'users' created or already present.")

    except mysql.connector.Error as exc:
        if exc.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("MySQL rejected credentials. Check MYSQL_USER and MYSQL_PASSWORD.")
        elif exc.errno == errorcode.ER_BAD_DB_ERROR:
            print(f"Unable to create or access database '{DATABASE}'.")
        elif 2000 <= exc.errno <= 2999:
            print(f"Connection issue: Could not reach MySQL at {HOST}:{PORT}.")
            print("If using Docker, ensure the container is active (`docker ps`).")
        else:
            print(f"Unexpected MySQL error: {exc}")

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def run():
    """
    Parses command-line flags and performs database initialization if required.
    """
    if "--init" in sys.argv:
        print("Starting database setup...")
        setup_database()
    else:
        print("Database management script.")
        print("Use '--init' to create the database and tables.")


if __name__ == "__main__":
    run()
