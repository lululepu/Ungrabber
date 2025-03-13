"""
This is the method template to use you can do anything you want as long as you
return the webhooks as webhooks in the dict (same for configs and token).
When you make a mehtods don't forget to add it to the __init__.py in the methods folder and
always name the file with the method name the same as the grabber name in the yara rules (yara/rules.yar)

"""

from .. import (
  utils,
  classes
)

def main(file: classes.Stub) -> dict:
  return {'webhooks': [], 'config': {}}