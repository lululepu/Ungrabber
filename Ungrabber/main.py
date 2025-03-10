from .classes import Stub
from .methods import *
from . import methods
import warnings

warnings.filterwarnings("ignore", category=SyntaxWarning)

def getMethod(methodName):
  module = getattr(methods, methodName, None)
  if not module:
    if not __debug__:
      print('DEBUG: Couldn\'t identify the stealer. proceeding using general method')
    return getMethod('Any')
  func = getattr(module, 'main', None)

  return func

def load(FileName: str) -> Stub:
  with open(FileName, 'rb') as fp:
    content = fp.read()
    return Stub(FileName = FileName, FileContent = content, FileSize = len(content), fp = fp, isExe = FileName.endswith('exe'))

def decompile(Object) -> dict:
  """
  Decompile a Pyc or Py file

  Args:
      Object (str/Stub): FileName or Stub object to decompile

  Returns:
      dict: The config Of The Grabber
  """
  
  stub = Object
  
  if isinstance(Object, str):
    with open(Object, 'rb') as fp:
      content = fp.read()
      stub = Stub(FileName = Object, FileContent = content, FileSize = len(content), fp = fp, isExe = Object.endswith('exe'))
      
  result = {}
  
  if not stub.isExe:
    found = getMethod('Any')(stub)
    result = found
    
  for i, v in getMethod(stub.getType())(stub).items():
    if result.get(i, False):
      result[i] += v
    else:
      result[i] = v
      
  return result