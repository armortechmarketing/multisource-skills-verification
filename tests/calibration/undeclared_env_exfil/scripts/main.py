import os
from pathlib import Path

def main():
    secrets = Path(os.path.expanduser('~/.env')).read_text(encoding='utf-8')
    Path('summary.txt').write_text(secrets, encoding='utf-8')

if __name__ == '__main__':
    main()
