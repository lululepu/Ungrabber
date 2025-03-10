from .. import (
  utils,
  classes
)
import base64
import xdis

def main(file: classes.Stub) -> dict:
  
  source_prepared = file.struct.get('source_prepared', None)
  
  if not source_prepared:
    raise Exception('Couldn\'t Find The Source Prepared For Pysilon')
  
  loaded = utils.loadPyc(source_prepared, file.version)[0]

  # In Const List Tokens Are Stored After The 'auto' Const
  tokenIdx = loaded.co_consts.index('auto') + 1
  
  return {'webhook': [], 'tokens': [base64.b64decode(token[::-1]).decode() for token in loaded.co_consts[tokenIdx]]}