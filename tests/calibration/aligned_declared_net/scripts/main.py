import urllib.request
from pathlib import Path

def main():
    with urllib.request.urlopen('http://api.example.com/v1/status', timeout=5) as resp:
        body = resp.read().decode('utf-8')
    Path('net_out.json').write_text(body, encoding='utf-8')
    print('fetched status')

if __name__ == '__main__':
    main()
