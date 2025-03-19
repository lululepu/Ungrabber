from .. import (
  utils,
  classes
)
from typing import *
from types import *
import zipfile
import base64
import zlib
import xdis
import re
import io

KeyIVRegex = re.compile(rb'stub-oz,([\w\d=]+)|([\d\w+/=]+)c\x03')

def getKeyIVFromLoader(loader: bytes, version: tuple[int, int]) -> tuple[bytes, int]:
  """
  Return Key And IV From Loader-O File

  Args:
      loader (bytes): The BlankGrabber Loader File

  Returns:
      tuple (bytes, int): The Key And IV
  """
  
  loaded = utils.loadPyc(loader, version)[0]
  
  # key, iv are at index 6 and 7 :3
  
  return (base64.b64decode(loaded.co_consts[6]), base64.b64decode(loaded.co_consts[7]))

def findLoader(struct: dict[str, bytes]) -> bytes:
  
  for i, v in struct.items():
    if b'stub-oz' in v:
      return v
  
  return None
  
def main(file: classes.Stub) -> dict:
  """
  Decompile A Compiled BlankGrabber

  Args:
      file (classes.File): `The file to decompile (exe)`

  Returns:
      str: `List Of Webhook/s found`
  """
  if not file.struct:
    file.generateStruct()

  # Get The Encrypted Payload
  loader_o = findLoader(file.struct)
  cipherText = file.struct.get('blank.aes', None)

  if not loader_o or not cipherText:
    raise FileNotFoundError('Tried To Decompile Invalid BlankGrabber')
  
  key, iv = getKeyIVFromLoader(loader_o, file.version)

  try:
    # Decompress the ciphertext (its reversed)
    uncompressed = zlib.decompress(cipherText[::-1])
  except:
    raise Exception('BlankGrabber Invalid cipherText')
  
  zipArchive = utils.AESDecrypt(key, iv, uncompressed)
  
  # Blank Grabber store the stub in a zip file
  with io.BytesIO(zipArchive) as fileBuffer:
    with zipfile.ZipFile(fileBuffer, 'r') as zipBuffer:
      with zipBuffer.open('stub-o.pyc', 'r') as stub:
        stubData = stub.read()
  
  # Deobfuscate the stub
  obfuscatedStub = utils.findLZMA(stubData)
  compiledStub = utils.BlankObfV1(obfuscatedStub)
  
  codeObj, VTuple, IsPypy, Opcode = utils.loadPyc(compiledStub, file.version)
  
  # Get Insts And Remove Cache Cause I Want To :<
  stubBadInsts = xdis.Bytecode(codeObj, Opcode).get_instructions(codeObj)
  stubInsts = filter(lambda x:x.opname.lower() != 'cache', stubBadInsts)
  
  # Find the settings code object
  for inst in stubInsts:
    if inst.opname != 'LOAD_CONST':
      continue
    if not isinstance(inst.argval, xdis.Code13) and not isinstance(inst.argval, CodeType):
      continue
    if inst.argval.co_name != 'Settings':
      continue
    
    setting_obj = inst.argval
    break
  
  if not setting_obj:
    raise Exception('Couldn\'t find the Settings object for BlankGrabber ')
  
  strings = [inst.argval for inst in xdis.Bytecode(setting_obj, Opcode).get_instructions(setting_obj) if inst.opname == 'LOAD_CONST']

  C2_idx = 0
  for i, v in enumerate(strings):
    if isinstance(v, str) and '/webhook' in v:
      C2_idx = i
      
  if not C2_idx:
    C2_idx = 3

  if not C2_idx:
    raise Exception('Couldn\'t find the C2 index for BlankGrabber (Could be using telegram that is not yet supported)')

  # Extract full config (ik that's alot)
  (
    C2,
    Mutex,
    PingMe,
    VmProtect,
    Startup,
    Melt,
    UacBypass,
    ArchivePassword,
    HideConsole,
    Debug,
    RunBoundOnStartup,
    CaptureWebcam,
    CapturePasswords,
    CaptureCookies,
    CaptureAutofills,
    CaptureHistory,
    CaptureDiscordTokens,
    CaptureGames,
    CaptureWifiPasswords,
    CaptureSystemInfo,
    CaptureScreenshot,
    CaptureTelegram,
    CaptureCommonFiles,
    CaptureWallets,
    FakeError,
    FakeErrorConfig,
    BlockAvSites,
    DiscordInjection
  ) = strings[C2_idx : C2_idx+28]
  
  return {
    'webhooks': [base64.b64decode(C2).decode()],
    'config': {
      'Mutex': base64.b64decode(Mutex).decode(),
      'PingMe': bool(PingMe),
      'VmProtect': bool(VmProtect),
      'Startup': bool(Startup),
      'Melt': bool(Melt),
      'UacBypass': bool(UacBypass),
      'ArchivePassword': base64.b64decode(ArchivePassword).decode(),
      'HideConsole': bool(HideConsole),
      'Debug': bool(Debug),
      'RunBoundOnStartup': bool(RunBoundOnStartup),
      'CaptureWebcam': bool(CaptureWebcam),
      'CapturePasswords': bool(CapturePasswords),
      'CaptureCookies': bool(CaptureCookies),
      'CaptureAutofills': bool(CaptureAutofills),
      'CaptureHistory': bool(CaptureHistory),
      'CaptureDiscordTokens': bool(CaptureDiscordTokens),
      'CaptureGames': bool(CaptureGames),
      'CaptureWifiPasswords': bool(CaptureWifiPasswords),
      'CaptureSystemInfo': bool(CaptureSystemInfo),
      'CaptureScreenshot': bool(CaptureScreenshot),
      'CaptureTelegram': bool(CaptureTelegram),
      'CaptureCommonFiles': bool(CaptureCommonFiles),
      'CaptureWallets': bool(CaptureWallets),
      'FakeError': bool(FakeError),
      'FakeErrorConfig': FakeErrorConfig,
      'BlockAvSites': bool(BlockAvSites),
      'DiscordInjection': bool(DiscordInjection)
    }
}