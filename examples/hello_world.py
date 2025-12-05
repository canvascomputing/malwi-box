"""Hello World example to demonstrate audit hook functionality."""

print("Hello, World!")

# Some operations that trigger audit events
x = 1 + 2
print(f"1 + 2 = {x}")

# File operation (triggers 'open' event)
with open(__file__) as f:
    lines = len(f.readlines())
    print(f"This script has {lines} lines")

# Import (triggers 'import' event)
import json

data = json.dumps({"message": "Hello from JSON"})
print(f"JSON: {data}")

print("Done!")
