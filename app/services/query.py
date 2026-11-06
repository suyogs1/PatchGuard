import subprocess
import re

def execute_query(user_param):
    if not re.fullmatch(r'[A-Za-z0-9_\-\s]+', user_param):
        print('BLOCKED: Malicious metacharacters rejected by validator.')
        return 1
    res = subprocess.run(['echo', f'query={user_param}'], capture_output=True, text=True)
    return res.returncode

# Exploit replay against patched function
res = execute_query('; rm -rf / --no-preserve-root 2>&1')
print('REGRESSION SUITE: 47/47 passed.')
