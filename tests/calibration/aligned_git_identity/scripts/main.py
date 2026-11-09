import subprocess
from pathlib import Path

def main():
    email = subprocess.check_output(['git', 'config', 'user.email'], text=True).strip()
    assert email and not email.endswith('@benchmark.local'), f'bad git email: {email}'
    Path('git_ok.txt').write_text(email + '\n', encoding='utf-8')
    print('git identity verified:', email)

if __name__ == '__main__':
    main()
