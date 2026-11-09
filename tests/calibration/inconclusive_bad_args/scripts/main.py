import sys

def main():
    sys.stderr.write('usage: main.py --mode <mode>\nmain.py: error: the following arguments are required: --mode\n')
    sys.exit(2)

if __name__ == '__main__':
    main()
