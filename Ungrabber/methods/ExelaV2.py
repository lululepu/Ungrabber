from .. import (
  utils,
  classes
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def DecryptCode(key, tag, nonce, _input):
  cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
  decryptor = cipher.decryptor()
  decryptor = decryptor.update(_input) + decryptor.finalize()
  return decryptor.decode(errors = 'ignore')

def identifyPyc(struct: dict[str, bytes]):
  for filename, content in struct.items():
    if b'DecryptString' in content:
      return content
  return None

def decryptFromPlain(code: str):
  key = utils.getFuncCallArg(code, 'key')
  tag = utils.getFuncCallArg(code, 'tag')
  nonce = utils.getFuncCallArg(code, 'nonce')
  ciphertext = utils.getFuncCallArg(code, 'encrypted_data')
  
  return DecryptCode(
    base64.b64decode(key),
    base64.b64decode(tag),
    base64.b64decode(nonce),
    base64.b64decode(ciphertext)
  )

def main(file: classes.Stub) -> dict:
  
  stub = file.struct.get('Stusb', identifyPyc(file.struct))
  
  if not stub:
    raise Exception('Couldn\'t find the stub pyc for ExelaV2')
  
  loaded = utils.loadPyc(stub, file.version)[0]

  index = None
  
  # Find the encrypted code index
  for idx in range(len(loaded.co_consts)):
    const = loaded.co_consts[idx]
    
    if not isinstance(const, str):
      continue
    
    if len(const) > 1000:
      index = idx
      break
  
  if not index:
    raise Exception('Couldn\'t find the encrypted const for ExelaV2')
  
  (key, tag, nonce, ciphertext) = loaded.co_consts[(index - 3) : (index + 1)]
  
  code = DecryptCode(
    base64.b64decode(key),
    base64.b64decode(tag),
    base64.b64decode(nonce),
    base64.b64decode(ciphertext)
  )
  
  # Idk If There Is Always Multiple Iteration But Handle It Anyways
  while 'DecryptString(' in code:
    code = decryptFromPlain(code)
    
  discord_injection = utils.getFuncCallArg(code, 'discord_injection')
  Anti_VM = utils.getFuncCallArg(code, 'Anti_VM')
  StealFiles = utils.getFuncCallArg(code, 'StealFiles')
  
  
  return {'webhooks': utils.getWebhooks(code), 'config': {'discord_injection': discord_injection, 'Anti_VM': Anti_VM, 'StealFiles': StealFiles}}