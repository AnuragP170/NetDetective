import mysql.connector

def main():
    output = []  # Initialize an empty list to store output
    conn = mysql.connector.connect(host='127.0.0.1', user='root', password='password', database='mysql')

    cursor = conn.cursor()
    output.append('\nCHECKING PRIVILEGES FOR USERS in mariadb system database')
    query = "SELECT * from user;"
    cursor.execute(query)
    results = cursor.fetchall()

    for row in results:
        if row[1] != 'root' and row[1] != 'mariadb.sys' and row[1] != 'mysql':
            user_output = [f'User: {row[1]}', 'Privileges']
            privileges = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'SHUTDOWN', 'PROCESS', 'FILE', 'GRANT', 'REFERENCES', 'INDEX', 'ALTER', 'SHOW DB', 'SUPER', 'CREATE TEMP TABLE', 'LOCK TABLES', 'EXECUTE', 'REPL SLAVES', 'CREATE VIEW', 'SHOW VIEW', 'CREATE ROUTINE', 'ALTER ROUTINE', 'CREATE USER', 'EVENT', 'TRIGGER', 'CREATE TABLESPACE', 'DELETE HISTORY']
            user_output.extend([f'{priv}: {row[i+3]}' for i, priv in enumerate(privileges)])
            output.append('\n'.join(user_output))

    cursor.close()
    conn.close()
    return '\n'.join(output)

# Example usage
if __name__ == "__main__":
    output = main()
    print(output)
