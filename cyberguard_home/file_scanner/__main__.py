import sys

from . import FileScanError, Verdict, scan_file

_LABELS = {Verdict.SAFE: "БЕЗОПАСНО", Verdict.SUSPICIOUS: "ПОДОЗРИТЕЛЬНО", Verdict.DANGEROUS: "ОПАСНО"}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Использование: python -m cyberguard_home.file_scanner <путь к файлу>")
        return 2
    try:
        result = scan_file(argv[1])
    except FileScanError as exc:
        print(exc)
        return 1
    print(f"Вердикт: {_LABELS[result.verdict]}")
    for reason in result.reasons:
        print(f" • {reason}")
    for note in result.skipped_checks:
        print(f" ! {note}")
    print(f"Что делать: {result.recommendation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))