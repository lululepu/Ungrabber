import Ungrabber
import cProfile
import xdis
import io
from types import CodeType


print(Ungrabber.decompile('exela.exe'))
print(Ungrabber.decompile('BlankGrabber.exe'))
print(Ungrabber.decompile('cstealer.exe'))
print(Ungrabber.decompile('pysilon.exe'))
print(Ungrabber.decompile('empyrean.exe'))


# loaded = Ungrabber.load('SWAT.exe')
# loaded.generateStruct()

# pyz = loaded.struct.get('PYZ-06.pyz', None)
# # print(pyz)
# extracted = Ungrabber.extract.extractPyz(io.BytesIO(pyz))

# def test(const):
#   res = []
#   for i in const:
#     print(i)
#     if isinstance(i, CodeType):
#       res.append(test(i.co_consts))
  
  
#   return res

# for name, value in extracted.items():
#   if not name.startswith('Saint'):
#     continue
  
#   load = Ungrabber.utils.loadPyc(value, loaded.pymin)[0]
#   print(test(load.co_consts))
#   # print(xdis.Bytecode(load, xdis.get_opcode(loaded.version, False)).dis())