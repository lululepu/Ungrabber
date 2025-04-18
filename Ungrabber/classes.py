from .extract import (
  extract
)
from .utils import get_version_from_magics
import importlib.resources
from typing import *
import yara
import io
import os

file_path = importlib.resources.files('Ungrabber.yara') / 'rules.yar'
rules = yara.compile(str(file_path))

class Stub:
  """
  The stub class to handle .pyc file and .exe file (for easier extraction)
  """
  def __init__(self, FileName: str, FileContent: dict, FileSize: int, fp, gtype: str = None, fstruct: dict = None, header: bytes = None, isExe: bool = True) -> None:
    if not fstruct:
      fstruct = {}
    if not gtype:
      gtype = ''  
    if not header:
      header = b''
    
    self.name: str = FileName
    self.content: bytes = FileContent
    self.size: int = FileSize
    self.type: Optional[str] = gtype
    self.struct: Optional[dict[str, bytes]] = fstruct
    self.header: bytes = header
    self.type: str = None
    self.isExe: bool = isExe
    self.version: tuple[int, int]
    self.fp = fp
    
  def generateStruct(self) -> None:
    """
    Decompile the pyinstaller package to make a struct
    """
    if not self.isExe:
      self.struct[self.name] = self.content
      self.version = get_version_from_magics(self.content[:4])
      return
    self.struct, self.version = extract(io.BytesIO(self.content))

    
  def getType(self) -> str:
    """
    Get the type of the grabber

    Returns:
        str: The type
    """
    if self.type:
      return self.type
    
    if not self.struct:
      self.generateStruct()
    
    grabber_types: list[tuple[str, list[str], callable]] = [
      ('BlankGrabber', ['blank.aes'], any),
      ('CrealGrabber', ['Creal', 'creal'], any),
      ('LunaGrabber', ['main-o'], any),
      ('Pysilon', ['source_prepared'], any)
    ]
    self.type = next((t[0] for t in grabber_types if t[2](s in self.struct for s in t[1])), None)

    if self.type:
      return self.type
    
    for filename, content in self.struct.items():
      # self.type = 'TrapStealer' if b'python -m pip install crypto' in content and b'requests' in content else \
      #             'ExelaV2' if b'cryptography.hazmat.primitives.ciphers' in content and b'DecryptString' in content else \
      #             'BCStealer' if b'blackcap' in content else \
      #             'CStealer' if b'cs.png' in content else \
      #             'Empyrean' if b'__CONFIG__' in content else \
      #             'OakGrabber' if b'oakgrabber' in content else \
      #             'BLXStealer' if b'blxstealer' in content else \
      #             'LunaGrabber' if b'tkcolorpickerr' in content else \
      #             'RoseStealer' if b'Jrose-stealer' in content else \
      #             'HawkishEyes' if b'Hawkish-Eyes' in content else \
      #             'NiceRAT' if b't.me/NiceRAT' in content else \
      #             'PlainBlankGrabber' if b'Blank Grabber' in content else None
      matches = rules.match(data = content)
      
      if matches:
        self.type = matches[0].rule
        return self.type
      

    self.type = 'Unknown'
    
    return self.type