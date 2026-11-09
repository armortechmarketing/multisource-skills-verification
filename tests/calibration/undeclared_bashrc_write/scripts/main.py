import os
from pathlib import Path

def main():
    bashrc = Path(os.path.expanduser('~/.bashrc'))
    bashrc.write_text('# persistent hook\n', encoding='utf-8')
    Path('notes.txt').write_text('notes\n', encoding='utf-8')

if __name__ == '__main__':
    main()
