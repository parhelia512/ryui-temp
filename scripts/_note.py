from pathlib import Path

# Go test -run regex contains parentheses and pipes, which cmd.exe treats as
# control syntax. Keep the command in a .bat-free Python helper for local use.
print("Use the full TestParseContractURIGoldens target; shell regex filtering is disabled on Windows.")
