import sqlite3
import pandas as pd

# Connect to the sample database file shown in your sidebar
db_path = "gitskills_raw/agent_skills_sample.db"
conn = sqlite3.connect(db_path)

# 1. List all tables in the database to see the structure
tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table';", conn)
print("Tables in database:")
print(tables)

# 2. View the first few rows of the main data table
# Note: Replace 'tables.iloc[0,0]' with the actual table name if you see it from step 1
if not tables.empty:
    target_table = tables.iloc[0, 0]
    df = pd.read_sql_query(f"SELECT * FROM {target_table} LIMIT 5;", conn)
    print(f"\nFirst 5 rows of '{target_table}':")
    print(df.head())
    
    # Print the column names so you know what features are available
    print("\nColumns:", df.columns.tolist())

conn.close()
