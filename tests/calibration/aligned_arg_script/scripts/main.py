import argparse
from pathlib import Path

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', required=True, help='Input file path')
    p.add_argument('--output', required=True, help='Output file path')
    args = p.parse_args()
    text = Path(args.input).read_text(encoding='utf-8')
    Path(args.output).write_text(text.upper(), encoding='utf-8')
    print('processed', args.output)

if __name__ == '__main__':
    main()
