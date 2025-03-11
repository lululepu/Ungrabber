from .. import (
  utils,
  classes,
  extract
)
import xdis
import io


def Deobf(comp: xdis.Code3, xor_table: list) -> str:

  # Extract The Values (remove the last one cause not needed)
  values = [round(abs(char)) for char in comp.co_consts][:-1]

  # Group Values Per 2 (Index, Value)
  grouped = zip(values[::2], values[1::2])
  
  # Sort Groups By Index
  sortedGroups = sorted(grouped, key = lambda x: x[0])

  # Decrypt Char By Char With xor_table[index]
  decrypted = ''.join(chr(value ^ xor_table[idx % len(xor_table)]) for idx, value in sortedGroups)
  
  return decrypted


def Extract(loadedPyc: xdis.Code3, version: tuple[int, int]) -> dict:
  
  xor_table = []
  
  pycObject = xdis.Bytecode(loadedPyc, xdis.get_opcode(version, False))

  insts = pycObject.get_instructions(loadedPyc)
  
  # Extract The Xor Table
  for inst in insts:
    if inst.opname == 'LOAD_CONST':
      xor_table.append(round(abs(inst.argval)))
    elif inst.opname ==  'STORE_NAME':
        break
      
  # Get Consts After The Xor Table  
  consts = [const for const in loadedPyc.co_consts[len(xor_table) + 1:] if isinstance(const, xdis.Code3)]

  # Create Config (store webhook first)
  config = [Deobf(consts[1], xor_table)]
  
  config.extend(inst.argval for inst in insts if inst.opname == 'LOAD_CONST' and isinstance(inst.argval, bool))
  
  __CONFIG__ = {
    'antidebug': config[1],
    'browsers': config[2],
    'discordtoken': config[3],
    'startup': config[4],
    'systeminfo': config[5],
  }
  
  return {'webhook': [config[0]], 'config': __CONFIG__}

def main(file: classes.Stub) -> list[str] | list[None]:
  
  pyz = file.struct.get('PYZ-00.pyz', file.struct.get('PYZ-00.pyzMEI', None))
  if not pyz:
    raise Exception('Couldn\'t Find The PYZ-00 For Empyrean Method')
  
  with io.BytesIO(pyz) as fp:
    config = extract.extractPyzFromName(fp, 'config')
    
  if not config:
    raise Exception('Couln\'t Find The Config File For Empyrean Method')
    
  pycTuple = utils.loadPyc(config, file.version)
  loaded = pycTuple[0]
  
  return Extract(loaded, file.version)