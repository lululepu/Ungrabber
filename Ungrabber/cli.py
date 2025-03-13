import sys
import Ungrabber

def ungrab():
  if len(sys.argv) > 1:
    for i, v in Ungrabber.decompile(sys.argv[1]).items():
      print(f'{i}: {v}')

if __name__ == '__main__':
  ungrab()