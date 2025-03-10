from .. import (
  utils,
  classes
)
import base64

def main(file: classes.Stub) -> dict:

  if file.isExe:
    source_prepared = file.struct.get('source_prepared', None)
  else:
    source_prepared = file.struct[file.name]
  
  if not source_prepared:
    raise Exception('Couldn\'t Find The Source Prepared For Pysilon')
  
  loaded = utils.loadPyc(source_prepared, file.version)[0]

  # In Const List Tokens Are Stored After The 'auto' Const
  tokenIdx = loaded.co_consts.index('auto') + 1

  if isinstance(loaded.co_consts[tokenIdx], tuple):
    tokens = [base64.b64decode(token[::-1]).decode() for token in loaded.co_consts[tokenIdx]]
  else:
    tokens = [base64.b64decode(loaded.co_consts[tokenIdx][::-1]).decode()]
    
  return {'webhooks': [], 'tokens': tokens}