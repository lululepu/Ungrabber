"""
MIT License

Copyright (c) 2024 lululepu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from uuid import uuid4
from Crypto.Cipher import AES
import xdis.codetype
from typing import *
from . import regs
from types import *
import base64
import codecs
import lzma
import xdis
import ast
import re
import io
import os

LZMASign = b'\xFD\x37\x7A\x58\x5A\x00'
moduleStartByte = (b'\xE3', b'\x63')

PY310 = b'\x6F\x0D\x0D\x0A'+b'\00'*12
PY311 = b'\xA7\x0D\x0D'+b'\x00'*13
PY312 = b'\xCB\x0D\x0D\x0A'+b'\00'*12

CODE_REF = b'\xE3'
CODE = b'\x63' # CODE_REF & ~128


def setHeader(pyc: bytes, header: bytes) -> bytes:
  """
  Set Given Header To The Pyc File Safely

  Args:
      pyc (bytes): The Target Pyc
      header (bytes): The Header To Set
      

  Returns:
      bytes: The Pyc With Modified Header
  """
  if pyc.startswith((CODE, CODE_REF)):
    return header + pyc
  
  return header + pyc[16:]


def getPycVersion(pyc: bytes) -> int:
  """
  Give You The Version Of A Pyc Without Header

  Args:
      pyc (bytes): The Target Pyc

  Returns:
      int: The PyMin Version
  """
  HEADERS = {
    10: PY310,
    11: PY311,
    12: PY312
  }
  
  for version, header in HEADERS.items():
    readyPyc = setHeader(pyc, header)
    print(readyPyc[:32])
    try: 
      xdis.load_module_from_file_object(io.BytesIO(readyPyc))
    except:
      continue
    return version

def isValidHeader(pyc: bytes):
  return pyc.startswith((PY310, PY311, PY312))

def getHeader(pymin: int) -> bytes:
  """
  This function give you the pyc header of the given python version

  Args:
      pymin (int): `The python min version`:
      ```
      11 = 3.11 , 12 = 3.12
      ```
  Returns:
      bytes: `The pyc header`
  """

  match pymin:
    case 10:
      return PY310
    case 11:
      return PY311
    case 12:
      return PY312
    case _:
      raise Exception(f'Unsupported version given to function: getHeader')
    
def getTToken(content: str) -> list:
  """
  Return a list of strings that match a telegram token regex in the given content

  Args:
      content (str): `The content to check`

  Returns:
      list: `The list of strings that match the regex`
  """
  return regs.TelegramToken.findall(content)

def getWebhooks(content) -> list:
  """
  Return a list of Plain webhooks/B64 Encoded webhoook found in a strings

  Args:
      content (str): `Text containing a webhook (plain/b64 webhook)`

  Returns:
      list: `List of webhook found (plain)`
  """
  
  content = str(content)
  
  encoded = sum([
    regs.DiscordB64Webhook.findall(content),
    regs.CanaryB64Webhook.findall(content),
    regs.PTBB64Webhook.findall(content),
    regs.DiscordAppB64Webhook.findall(content)
  ], [])

  founds = [base64.b64decode(webhook) for webhook in encoded]
    
  founds.extend(regs.DiscordWebhook.findall(content))
  return founds or None

def getVar(code: str, var: str) -> str:
  """
  Get an var value in a code from name

  Args:
      code (str): `The code to analyse`
      var (str): `The name of the var to retrieve`

  Returns:
      str: `The value of the var`
  """
  
  astTree = ast.parse(code)
  for node in ast.walk(astTree):
    if isinstance(node, ast.Assign):
      for target in node.targets:
        if isinstance(target, ast.Name) and target.id == var:
          return node.value.value


def getFuncCallArg(code: str, varname: str) -> str:
  """
  Get a arg from a function call example:
  ```
  code = '''key = base64.b64encode('Test')'''
  print(getFuncCallArg(code, 'key')))
  ```
  `This will return 'Test'`

  Args:
      code (str): `The code to analyse`
      varname (str): `The name of the var to retrieve`

  Returns:
      str: `The arg of the func call`
  """
  
  astTree = ast.parse(code)
  for node in ast.walk(astTree):
    if isinstance(node, ast.Assign):
      for target in node.targets:
        if isinstance(target, ast.Name) and target.id == varname:
          return node.value.args[0].value

def AESDecrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
  """
  Decrypt AES encrypter ciphertext

  Args:
      key (bytes): `The secret key to use in the symmetric cipher.`
      iv (bytes): `The initialization vector to use for encryption or decryption.`
      ciphertext (bytes): `The piece of data to decrypt.`

  Returns:
      bytes: Decrypted Plain Text
  """
  cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
  decrypted = cipher.decrypt(ciphertext)
  return decrypted

def DetectObfuscator(code: bytes):
  if isinstance(code, str):
    code = code.encode()
  
  if b'___________' in code:
    if findLZMA(code):
      return 'BlankObf'
  
  return None

def BlankObfV1(code: str) -> str:
  """
  Deobfuscate BlankObfV1 Plain Obfuscation

  Args:
      code (str): `The code to deobfuscate`

  Returns:
      str: `The deobfuscated code`
  """
  ____ = getVar(code, '____')
  _____ = getVar(code, '_____')
  ______ = getVar(code, '______')
  _______ = getVar(code, '_______')
  deobfuscated = base64.b64decode(codecs.decode(____, 'rot13')+_____+______[::-1]+_______)
  content = deobfuscated
  return content

def findLZMA(content: bytes) -> bytes:
  """
  Find An Lzma Signature And Return The Decompressed Content

  Args:
      content (bytes): The Buffer To Search

  Returns:
      bytes: The Decompressed LZMA
  """
  return lzma.decompress(LZMASign + content.split(LZMASign)[-1])

def loadPyc(pyc: bytes, version: tuple[int, int]) -> tuple[xdis.Code3, tuple[int,int], bool, ModuleType]:
  """
  Load Pyc With Header Or Not

  Args:
      pyc (bytes): `The Target Pyc`

  Returns:
      tuple (xdis.codetype.CodeBase, tuple[int,int], bool, ModuleType): `A Tuple Of Info (CodeObj, VersionTuple, isPypy, OpCode)`
  """
  
  if not isValidHeader(pyc):
    pyc = setHeader(pyc, getHeader(version[1]))
    
  open('caca.pyc', 'wb').write(pyc)
  loaded = xdis.load_module_from_file_object(io.BytesIO(pyc))
  
  version_tuple = loaded[0]
  code_obj = loaded[3]
  ispypy = loaded[4]
  opcode = xdis.get_opcode(version_tuple, ispypy)
  
  return (code_obj, version_tuple, ispypy, opcode)