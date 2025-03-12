from .. import (
  utils,
  classes
)

def DeobfBlank(file: bytes):
  code = utils.findLZMA(file)
  return utils.BlankObfV1(code.decode())

def scanFile(file: bytes) -> list:
  """
  This function scan a file for plain/encoded webhook and obfuscation

  Args:
      file (bytes): The file to analyze

  Returns:
      list: The webhooks found
  """
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
    # Skip useless files
    if name.endswith(('.pyd','.dll','MEI')):
      continue
    else:
      found.extend(scanFile(content))

  return {'webhooks': found}