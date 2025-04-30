from .utils import mergeAdd
from .classes import Stub
from .methods import *
from . import methods
import warnings
import io

warnings.filterwarnings("ignore", category=SyntaxWarning)

def getMethod(methodName):
  """
  Get a method from the methods folder by name (Return Any method if not found)

  Args:
      methodName (str): The method name

  Returns:
      Function: The main function of the method
  """
  module = getattr(methods, methodName, None)
  if not module:
    if not __debug__:
      print('DEBUG: Couldn\'t identify the stealer. proceeding using general method')
    return getMethod('Any')
  func = getattr(module, 'main', None)

  if not func:
    raise Exception('Could\'nt find the method for {methodName}, forgot to import in methods/__init__.py ?')
  
  return func

def loads(buffer: bytes) -> Stub:
  """
  Get a stub object for a given file from buffer (raw pyc/exe) 

  Args:
      buffer (bytes): The buffer for the file

  Returns:
      Stub: The stub object of the file
  """

  return Stub(FileName = 'placeholder', FileContent = buffer, FileSize = len(buffer), fp = io.BytesIO(buffer), isExe = buffer.startswith(b'MZ'))

def load(fp: io.BufferedReader) -> Stub:
  """
  Get a stub object for a given file from name

  Args:
      FileName (str): The Name of the file to load

  Returns:
      Stub: The stub object of the file
  """
  content = fp.read()
  fp.seek(0)
  return Stub(FileName = 'placeholder', FileContent = content, FileSize = len(content), fp = fp, isExe = content.startswith(b'MZ'))

def decompile(Object: str | Stub) -> dict:
  """
  Decompile a Pyc or Py file

  Args:
      Object (str/Stub): FileName or Stub object to decompile

  Returns:
      dict: The config Of The Grabber
  """
  
  
  if isinstance(Object, str):
    with open(Object, 'rb') as fp:
      content = fp.read()
      Object = Stub(FileName = Object, FileContent = content, FileSize = len(content), fp = fp, isExe = content.startswith(b'MZ'))

  result = {'webhooks': []}
   
  if not Object.isExe:
    found = getMethod('Any')(Object)
    result = found
  
  result = mergeAdd(result, getMethod(Object.getType())(Object))
  
  if len(result['webhooks']) < 1:
    result = mergeAdd(result, getMethod('Any')(Object))
  
  return result