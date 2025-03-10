from .. import (
  utils,
  classes
)

def DeobfBlank(file: bytes):
  code = utils.findLZMA(file)
  return utils.BlankObfV1(code.decode())

def scanFile(file: bytes) -> list:
  founds = []
  
  founds.extend(utils.getWebhooks(file))  

  obfuscator = utils.DetectObfuscator(file)
  if not obfuscator:
    return founds

  match obfuscator:
    case 'BlankObf':
      founds.extend(scanFile(DeobfBlank(file)))
      
  return founds

def main(file: classes.Stub) -> dict:
  
  found = []
  
  for name, content in file.struct.items():
    if name.endswith(('.pyd','.dll','MEI')):
      continue
    else:
      found.extend(scanFile(content))

  return {'webhooks': found}