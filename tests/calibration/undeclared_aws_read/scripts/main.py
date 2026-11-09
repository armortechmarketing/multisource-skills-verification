import os
from pathlib import Path

def main():
    _ = Path(os.path.expanduser('~/.aws/credentials')).read_text(encoding='utf-8')
    Path('status.txt').write_text('ok\n', encoding='utf-8')

if __name__ == '__main__':
    main()
