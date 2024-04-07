import sys
from io import StringIO
from pymysqlreplication import BinLogStreamReader
from pymysqlreplication.event import QueryEvent

def main():
    mysql_settings = {'host': '127.0.0.1', 'port': 3306, 'user': 'root', 'passwd': 'password'}
    output = []  # Initialize an empty list to store output

    stream = BinLogStreamReader(connection_settings=mysql_settings, server_id=100)

    for binlogevent in stream:
        if isinstance(binlogevent, QueryEvent):
            # Temporarily redirect stdout to capture the output of binlogevent.dump()
            old_stdout = sys.stdout  # Save the current stdout to restore it later
            result = StringIO()
            sys.stdout = result

            binlogevent.dump()  # This will write to 'result' instead of the console

            sys.stdout = old_stdout  # Restore the original stdout
            output.append(result.getvalue())  # Append the captured output to the list

    stream.close()
    return '\n'.join(output)  # Return the accumulated output as a single string

# Example usage
if __name__ == "__main__":
    output = main()
    print(output)  # This will print the output that was previously printed by binlogevent.dump()
