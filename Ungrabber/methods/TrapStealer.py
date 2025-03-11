# I know this take too much time imma try optimizing it later on

from json import load
from .. import (
  utils,
  classes
)
from fernet import Fernet
from types import CodeType
import base64
import ast

# Optimized version of the real function :3
def DeobfuscateWeb(ciphertext, key):
  decrypted = {char: i for i, char in enumerate(key)}
  return bytes(decrypted[char] for char in ciphertext)

def Decrypt(data, key) -> str:
  firstLayer = Fernet(key).decrypt(base64.b85decode(data))
  decodedFL = base64.b85decode(firstLayer)
  secondLayer = bytes((i % 94 + 32) for i in range(len(decodedFL)))
  result = bytes(a ^ b for a, b in zip(decodedFL, secondLayer))
  return result.decode()


def findMainPyc(struct: dict[str, bytes]):
  for name, content in struct.items():
    if b'check_debug' in content:
      return content

def main(file: classes.Stub) -> dict:
  
  mainPyc = findMainPyc(file.struct)
  
  loaded = utils.loadPyc(mainPyc, file.version)[0]
  
  func1 = loaded.co_consts[loaded.co_consts.index('__main__') - 2]
  func2 = func1.co_consts[-3]
  
  for const in func2.co_consts:
    if not isinstance(const, str):
      continue
    if len(const) > 500:
      ciphertext = const
      break
      
  if not ciphertext:
    raise Exception('Couldn\'t find the ciphertext for TrapStealer')
  
  func3 = func1.co_consts[2]
  key = func3.co_consts[-2]
 
  if not key:
    raise Exception('Couldn\'t find the key for TrapStealer')
  
  code = Decrypt(ciphertext, key)
  
  
  encwb, keywb = [i.value for i in utils.getVar(code, 'webhook').elts] 
  
  config = {
    "logfile": utils.getVarConst(code, 'logfile'),
    "debug": utils.getVarConst(code, 'debug'),
    "FakeWebhook": utils.getVarConst(code, 'FakeWebhook'),
    "Fakegen": utils.getVarConst(code, 'Fakegen'),
    "FakeCCgen": utils.getVarConst(code, 'FakeCCgen'),
    "FakeError": utils.getVarConst(code, 'FakeError'),
    "schedule": utils.getVarConst(code, 'schedule'),
    "injection": utils.getVarConst(code, 'injection'),
    "Startup": utils.getVarConst(code, 'Startup'),
    "antidebugging": utils.getVarConst(code, 'antidebugging'),
    "DiscordStop": utils.getVarConst(code, 'DiscordStop'),
    "OneTimeSteal": utils.getVarConst(code, 'OneTimeSteal'),
    "melter": utils.getVarConst(code, 'melter'),
    "crasher": utils.getVarConst(code, 'crasher'),
    "hidewindow": utils.getVarConst(code, 'hidewindow'),
    "changebio": utils.getVarConst(code, 'changebio'),
    "Drive": utils.getVarConst(code, 'Drive'),
    "close_proc": utils.getVarConst(code, 'close_proc'),
    "ArchiStealer": utils.getVarConst(code, 'ArchiStealer'),
    
    # WEBSITE UPLOAD
    "Gofile": utils.getVarConst(code, 'Gofile'),
    "fileio": utils.getVarConst(code, 'fileio'),
    "catbox": utils.getVarConst(code, 'catbox'),
    
    # TRAP EXTENSION
    "trap_extension": utils.getVarConst(code, 'trap_extension'),
    "Iban_Stealer": utils.getVarConst(code, 'Iban_Stealer')
  }
  
  
  if not encwb:
    raise Exception('Failed to found the encrypted webhook for TrapStealer')
  
  return {'webhooks': [DeobfuscateWeb(encwb, keywb).decode()], 'config': config}