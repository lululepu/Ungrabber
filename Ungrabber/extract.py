from .utils import (
  getHeader
)

from uuid import uuid4 as uniquename
import struct
import zlib
import os

class CTOCEntry:
  def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
    self.position = position
    self.cmprsdDataSize = cmprsdDataSize
    self.uncmprsdDataSize = uncmprsdDataSize
    self.cmprsFlag = cmprsFlag
    self.typeCmprsData = typeCmprsData
    self.name = name

class PyInstArchive:
  PYINST20_COOKIE_SIZE = 24
  PYINST21_COOKIE_SIZE = 24 + 64
  MAGIC = b'MEI\014\013\012\013\016'

  def __init__(self, content):
    self.barePycList = []
    self.fileContent = content
    self.pycMagic = b'\0' * 4
    self.archiveDict = {}
      
  def checkFile(self):
    searchChunkSize = 8192
    endPos = len(self.fileContent)
    self.cookiePos = -1

    if endPos < len(self.MAGIC):
      return False

    while True:
      startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
      chunkSize = endPos - startPos

      if chunkSize < len(self.MAGIC):
        break

      data = self.fileContent[startPos:endPos]

      offs = data.rfind(self.MAGIC)

      if offs != -1:
        self.cookiePos = startPos + offs
        break

      endPos = startPos + len(self.MAGIC) - 1

      if startPos == 0:
        break

    if self.cookiePos == -1:
      return False

    if b'python' in self.fileContent[self.cookiePos + self.PYINST20_COOKIE_SIZE:self.cookiePos + self.PYINST20_COOKIE_SIZE + 64].lower():
      self.pyinstVer = 21
    else:
      self.pyinstVer = 20

    return True

  def getCArchiveInfo(self):
    try:
      if self.pyinstVer == 20:
        (magic, lengthofPackage, toc, tocLen, pyver) = struct.unpack('!8siiii', self.fileContent[self.cookiePos:self.cookiePos + self.PYINST20_COOKIE_SIZE])
      elif self.pyinstVer == 21:
        (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = struct.unpack('!8sIIii64s', self.fileContent[self.cookiePos:self.cookiePos + self.PYINST21_COOKIE_SIZE])
    except:
      return False

    self.pymaj, self.pymin = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
    print(self.pymaj, self.pymin)
    globals()['headers'] = getHeader(self.pymin)


    tailBytes = len(self.fileContent) - self.cookiePos - (self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE)
    self.overlaySize = lengthofPackage + tailBytes
    self.overlayPos = len(self.fileContent) - self.overlaySize
    self.tableOfContentsPos = self.overlayPos + toc
    self.tableOfContentsSize = tocLen

    return True

  def parseTOC(self):
    self.tocList = []
    parsedLen = 0

    while parsedLen < self.tableOfContentsSize:
      (entrySize,) = struct.unpack('!i', self.fileContent[self.tableOfContentsPos:self.tableOfContentsPos + 4])
      nameLen = entrySize - struct.calcsize('!IIIBc')
      (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = struct.unpack(
          '!IIIBc{0}s'.format(nameLen),
          self.fileContent[self.tableOfContentsPos + 4:self.tableOfContentsPos + 4 + entrySize])

      try:
        name = name.decode("utf-8").rstrip("\0")
      except UnicodeDecodeError:
        newName = str(uniquename())
        name = newName

      if len(name) == 0:
        name = str(uniquename())
        
      name = name.replace('\x00', '')[:-1]
      self.tocList.append(
          CTOCEntry(
              self.overlayPos + entryPos,
              cmprsdDataSize,
              uncmprsdDataSize,
              cmprsFlag,
              typeCmprsData,
              name
          )
      )

      parsedLen += entrySize
      self.tableOfContentsPos += entrySize

  def extractFiles(self):
    for entry in self.tocList:
      data = self.fileContent[entry.position:entry.position + entry.cmprsdDataSize]
      
      if entry.cmprsFlag == 1:
        try:
          data = zlib.decompress(data)
        except zlib.error:
          continue

      if entry.typeCmprsData == b'd' or entry.typeCmprsData == b'o':
        continue

      content = None

      if entry.typeCmprsData == b's':
        if self.pycMagic == b'\0' * 4:
          self.barePycList.append(entry.name + '.pyc')
        content = self._readPyc(data)

      elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
        if data[2:4] == b'\r\n':
          if self.pycMagic == b'\0' * 4:
            self.pycMagic = data[0:4]
          content = data
        else:
          content = self._readPyc(data)

      else:
        content = data

      self.addToDict(entry.name, content)

      if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
        self._extractPyz(entry.name)

  def addToDict(self, filename, content):
    parts = filename.split(os.path.sep)
    current_dict = self.archiveDict
    for part in parts[:-1]:
      if part not in current_dict:
        current_dict[part] = {}
      current_dict = current_dict[part]
    current_dict[parts[-1]] = content

  def _readPyc(self, data):
    content = bytearray()
    content.extend(self.pycMagic)
    content.extend(struct.pack('!I', len(data)))
    content.extend(data)
    return content

  def _extractPyz(self, name):
    ...

def Extract(file_content) -> dict:
  arch = PyInstArchive(file_content)
  if arch.checkFile():
    if arch.getCArchiveInfo():
      arch.parseTOC()
      arch.extractFiles()
      return (arch.archiveDict, arch.pymin)