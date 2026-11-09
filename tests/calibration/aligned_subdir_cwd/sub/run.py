from pathlib import Path

def main():
    cfg = Path('local_cfg.txt').read_text(encoding='utf-8').strip()
    assert cfg == 'CFG_OK', f'unexpected cfg: {cfg}'
    Path('sub_out.txt').write_text('SUB_DONE\n', encoding='utf-8')
    print('subdir ok')

if __name__ == '__main__':
    main()
