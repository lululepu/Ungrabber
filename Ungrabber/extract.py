# TODO: Make the extractor in c++ for better performances

import io
import os
import zlib
import struct
import marshal
from dataclasses import dataclass

pyinstHeaderSign = b'MEI\x0C\x0B\n\x0B\x0E'

@dataclass
class PyinstHeader:
  Signature: bytes
  PackageSize: int
  TOCoffset: int
  TOCsize: int
  PythonVersion: int
  
  @staticmethod
  def parse(fp: io.BufferedReader, headerOffset: int) -> "PyinstHeader":
    
    fp.seek(headerOffset)
    
    header = PyinstHeader(
      fp.read(len(pyinstHeaderSign)),
      struct.unpack('!I', fp.read(4))[0],
      struct.unpack('!I', fp.read(4))[0],
      struct.unpack('!I', fp.read(4))[0],
      struct.unpack('!I', fp.read(4))[0]
    )

    return header

@dataclass
class PyinstEntry:
  Size: int
  Offset: int
  CompressedSize: int
  UncompressedSize: int
  CompressionFlag: int
  type: int
  name: str
  
  @staticmethod
  def parse(fp: io.BufferedReader, overlayOffset: int) -> "PyinstEntry":
    
    size = struct.unpack('!I', fp.read(4))[0]
    
    # TotalSize - ((Size) Size + (Offset) Size + (CompressedSize) Size + (UncompressedSize) Size + (CompressionFlag) Size + (type) Size)
    nameSize = size - (4 + 4 + 4 + 4 + 1 + 1)
  
    entry = PyinstEntry(
      size,
      overlayOffset + struct.unpack('!I', fp.read(4))[0],
      struct.unpack('!I', fp.read(4))[0],
      struct.unpack('!I', fp.read(4))[0],
      struct.unpack('c', fp.read(1))[0],
      struct.unpack('c', fp.read(1))[0],
      ''
    )
    
    try:
      entry.name = fp.read(nameSize).replace(b'\x00', b'').decode()
    except:
      entry.name = 'InvalidName'
    

    return entry

def getHeaderOffset(fp: io.BufferedReader):
  content = fp.read()
  pyInstHeader = content.rfind(pyinstHeaderSign)
  
  return pyInstHeader

def processEntry(fp: io.BufferedReader, entry: PyinstEntry):
  
  if entry.CompressedSize == 0:
    return b''
  
  content = fp.read(entry.CompressedSize)

  if content.startswith(b'PYZ'):
    return content

  return zlib.decompress(content)

def extract(fp: io.BufferedReader) -> tuple[dict, tuple[int, int]]:
    fp.seek(0, os.SEEK_SET)
    headerOffset = getHeaderOffset(fp)
    
    filesize = fp.seek(0, os.SEEK_END)
    
    fp.seek(headerOffset + 24)
    
    # Extract The Pyinstaller Header
    pyInstHeader = PyinstHeader.parse(fp, headerOffset)
    
    currPos = fp.tell()
    addBytes = fp.seek(0, os.SEEK_END) - currPos - 64


    version = (pyInstHeader.PythonVersion//100, pyInstHeader.PythonVersion % 100)

    # Get The Overlay Offset Relative To The File Start
    overlayOffset = filesize - pyInstHeader.PackageSize - addBytes

    fp.seek(overlayOffset + pyInstHeader.TOCoffset)
    
    bytesRead = 0
    TOC: list[PyinstEntry] = []
    
    # Extract TOC Objects
    while bytesRead < pyInstHeader.TOCsize:
      entry = PyinstEntry.parse(fp, overlayOffset)
      bytesRead += entry.Size
      TOC.append(entry)

    fp.seek(overlayOffset)
    
    result = {entry.name: processEntry(fp, entry) for entry in TOC}
    
    return (result, version)

def getPyzTOC(fp: io.BufferedReader):
  
  # Skip The Header
  fp.seek(8)
  
  (tocPosition, ) = struct.unpack('!i', fp.read(4))
  
  fp.seek(tocPosition, os.SEEK_SET)
  
  TOC = marshal.load(fp)
  
  return TOC

def extractPyzFromName(fp: io.BufferedReader, filename: str):

  TOC = getPyzTOC(fp)
  
  entry = next((x for x in TOC if x[0] == filename), None)

  if not entry:
    return None
  
  (name, (ispkg, pos, length)) = entry
  
  fp.seek(pos)
  
  return zlib.decompress(fp.read(length))

def extractPyz(fp: io.BufferedReader) -> dict[str, bytes]:
  
  TOC = getPyzTOC(fp)
  
  firstEntryPos = TOC[0][1][1]
  
  fp.seek(firstEntryPos)
  
  result = {}
  
  for entry in TOC:
    (name, (ispkg, pos, length)) = entry
    result[name] = zlib.decompress(fp.read(length))
  
  return result