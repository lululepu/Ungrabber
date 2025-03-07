from .. import (
  utils,
  classes
)
import marshal
import struct
import zlib
import xdis
import io
import os

xor_table = []

def Deobf(comp: xdis.Code3, version: tuple[int, int]) -> str:

  # Extract The Values (remove the last one cause not needed)
  values = [round(abs(char)) for char in comp.co_consts][:-1]

  # Group Values Per 2 (Index, Value)
  grouped = [(values[i], values[i+1]) for i in range(0, len(values) - 1, 2)]
  
  # Sort Groups By Index
  sortedGroups = sorted(grouped, key = lambda x: x[0])

  # Decrypt Char By Char With xor_table[index]
  decrypted = ''.join([chr(value ^ xor_table[idx % len(xor_table)]) for idx, value in sortedGroups])
  
  return decrypted


def Extract(loadedPyc: xdis.Code3, version: tuple[int, int]) -> str:
  
  pycObject = xdis.Bytecode(loadedPyc, xdis.get_opcode(version, False))

  # Get Insts And Get Rid Of Cache (ts pmo)
  insts = (inst for inst in pycObject.get_instructions(loadedPyc) if inst.opname != 'CACHE')
  
  # Extract The Xor Table
  for inst in insts:
    opname, argval = inst.opname, inst.argval
    
    match opname:
      case 'LOAD_CONST':
        xor_table.append(round(abs(argval)))
      case 'STORE_NAME':
        break
  
  # Get Consts After The Xor Table  
  consts = [const for const in loadedPyc.co_consts[len(xor_table) + 1:] if isinstance(const, xdis.Code3)]

  # Create Config (store webhook first)
  config = [Deobf(consts[1], version)]
  
  for inst in insts:
    if inst.opname == 'LOAD_CONST':
      if isinstance(inst.argval, bool):
        config.append(inst.argval)
  
  __CONFIG__ = {
    'webhooks': [config[0]],
    'antidebug': config[1],
    'browsers': config[2],
    'discordtoken': config[3],
    'startup': config[4],
    'systeminfo': config[5],
  }
  
  return __CONFIG__

def main(file: classes.Stub) -> list[str] | list[None]:
  
  pyz = file.struct.get('PYZ-00.pyz', file.struct.get('PYZ-00.pyzMEI', None))
  if not pyz:
    raise Exception('Couldn\'t Find The PYZ-00 For Empyrean Method')
  
  # Using A Bytes Buffer Cause It's Better
  fp = io.BytesIO(pyz)
  
  # Skip The Header
  fp.seek(8)
  
  (tocPosition, ) = struct.unpack('!i', fp.read(4))
  
  fp.seek(tocPosition, os.SEEK_SET)
  
  TOC = marshal.load(fp)
  
  # Get The Config Toc Entry
  config = next((x for x in TOC if x[0] == 'config'), None)
  
  (name, (ispkg, pos, length)) = config
  
  fp.seek(pos, os.SEEK_SET)
  
  encodedPyc = fp.read(length)
  content = zlib.decompress(encodedPyc)

  pycTuple = utils.loadPyc(content, file.pymin)
  loaded = pycTuple[0]
  
  return Extract(loaded, (3, file.pymin))