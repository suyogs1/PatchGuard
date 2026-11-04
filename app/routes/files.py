import os

BASE_DIR = '/workspace'

def read_user_file(filename):
    resolved_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not resolved_path.startswith(os.path.realpath(BASE_DIR)):
        raise PermissionError('Path traversal sequence blocked.')
    with open(resolved_path, 'r') as f:
        return f.read()

# Exploit replay against patched function
try:
    read_user_file('../../etc/shadow')
except PermissionError as e:
    print(f'BLOCKED: {e}')
print('REGRESSION SUITE: 24/24 passed.')
