from .. import (
  utils,
  classes
)


def main(file: classes.Stub) -> dict:
  
  found = []
  
  for name, content in file.struct.items():
    if name.endswith(('.pyd','.dll','MEI')):
      continue
    else:
      wbs = utils.getWebhooks(content)
      if wbs:
        found.extend(wbs)

  return {'webhooks': found}