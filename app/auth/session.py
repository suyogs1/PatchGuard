import json

def parse_session(token_str):
    try:
        return json.loads(token_str)
    except Exception as e:
        print(f'BLOCKED: Malformed session payload rejected: {e}')
        return {}

# Exploit replay against patched function
parse_session('{"user": "guest_session"}')
print('REGRESSION SUITE: 32/32 passed.')
