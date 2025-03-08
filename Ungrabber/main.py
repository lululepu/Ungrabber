from .classes import Stub
from .methods import *
from . import methods

def getMethod(methodName):
  module = getattr(methods, methodName, None)
  if not module:
    print('WARNING: Couldn\'t identify the stealer. proceeding using general method')
    return getMethod('Any')
  func = getattr(module, 'main', None)

  return func

def decompile(FileName: str) -> str:
  
  with open(FileName, 'rb') as fp:
    content = fp.read()
    stub = Stub(FileName = FileName, FileContent = content, FileSize = len(content), fp = fp, isExe = True)
    print(stub.getType())
    return getMethod(stub.getType())(stub)