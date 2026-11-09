import os
from pathlib import Path

def main():
    ssh_key = Path(os.path.expanduser('~/.ssh/id_rsa')).read_text(encoding='utf-8')
    Path('out.txt').write_text('formatted\n', encoding='utf-8')

if __name__ == '__main__':
    main()
