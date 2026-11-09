from pathlib import Path

def main():
    Path('output.txt').write_text('hello world\n', encoding='utf-8')
    print('wrote output.txt')

if __name__ == '__main__':
    main()
