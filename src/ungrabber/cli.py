import sys
from ungrabber import decompile


def ungrab():
    if len(sys.argv) > 1:
        for i, v in decompile(sys.argv[1]).items():
            print(f"{i}: {v}")


if __name__ == "__main__":
    ungrab()
