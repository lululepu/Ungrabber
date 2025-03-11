from .extract import (
  extract
)
from .utils import get_version_from_magics
from typing import *
import io

class Stub:
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
    if not self.isExe:
      self.struct[self.name] = self.content
      self.version = get_version_from_magics(self.content[:4])
      return
    self.struct, self.version = extract(io.BytesIO(self.content))

    
  def getType(self) -> str:
    
    if self.type:
      return self.type
    
    if not self.struct:
      self.generateStruct()
    # self.type = 'BlankGrabber' if 'blank.aes' in self.struct else \
    #             'LunaGrabberV2' if 'luna.aes' in self.struct or 'bound.luna' in self.struct else \
    #             'CrealGrabber' if 'Creal' in self.struct or 'creal' in self.struct else \
    #             'LunaGrabber' if 'main-o' in self.struct else \
    #             'Pysilon' if 'source_prepared' in self.struct else None
    
    self.type = 'BlankGrabber' if 'blank.aes' in self.struct else \
            'CrealGrabber' if 'Creal' in self.struct or 'creal' in self.struct else \
            'LunaGrabber' if 'main-o' in self.struct else \
            'Pysilon' if 'source_prepared' in self.struct else None

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
      self.type = 'TrapStealer' if b'detect_debugger_timing' in content else \
            'BCStealer' if b'blackcap' in content else \
            'CStealer' if b'cs.png' in content else \
            'Pysilon' if b'PySilon' in content else \
            'ExelaV2' if b'cryptography.hazmat.primitives.ciphers' in content and b'DecryptString' in content else \
            'Empyrean' if b'__CONFIG__' in content else \
            'LunaGrabber' if b'tkcolorpickerr' in content else \
            'HawkishEyes' if b'Hawkish-Eyes' in content else \
            'NiceRAT' if b't.me/NiceRAT' in content else \
            'PlainBlankGrabber' if b'Blank Grabber' in content else None
                  
      if self.type:
        return self.type

    self.type = 'Unknown'
    
    return self.type