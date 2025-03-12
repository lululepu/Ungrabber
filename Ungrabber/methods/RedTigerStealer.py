from .. import (
  utils,
  classes
)


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

def findMainPyc(struct: dict[str, bytes]):
  for name, content in struct.items():
    if b'redtiger.shop' in content:
      return content

def DeriveKey(password, salt):
  kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000, default_backend())
 
  if isinstance(password, str):
    password = password.encode()
    
  return kdf.derive(password)

def Decrypt(ciphertext, key) -> str:
  decoded = base64.b64decode(ciphertext)
  salt = decoded[:16]
  iv = decoded[16:32]
  decoded = decoded[32:]
  derived_key = DeriveKey(key, salt)
  cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend = default_backend())
  decryptor = cipher.decryptor()
  decrypted_data = decryptor.update(decoded) + decryptor.finalize()
  unpadder = padding.PKCS7(128).unpadder()
  return (unpadder.update(decrypted_data) + unpadder.finalize()).decode()

def main(file: classes.Stub) -> dict:
  
  mainPyc = findMainPyc(file.struct)
  
  
  loaded = utils.loadPyc(mainPyc, file.version)[0]
  
  # index of const below - 1 = key, - 2 = ciphertext
  
  # Use this const cause its unique
  try:
    constIdx = loaded.co_consts.index('RedTiger Ste4ler - github.com/loxy0dev/RedTiger-Tools')
  except:
    return {'webhooks': []}
  
  key = loaded.co_consts[constIdx - 1]
  ciphertext = loaded.co_consts[constIdx - 2]
  

  return {'webhooks': [Decrypt(ciphertext, key)], 'config': {}}