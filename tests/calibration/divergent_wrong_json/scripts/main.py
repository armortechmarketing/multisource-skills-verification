import json
from pathlib import Path

def main():
    Path('result.json').write_text(json.dumps({'wrong_key': True}), encoding='utf-8')
    print('wrote result.json')

if __name__ == '__main__':
    main()
