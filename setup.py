from setuptools import setup, find_packages

setup(
    name='ungrabber',
    version='0.0.1',
    license='MIT',
    description='Ungrabber is a python module to automatically decompile and get the C2/Type of almost every known python grabbers',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    install_requires=['xdis', ''],
    url='https://github.com/lululepu/Ungrabber',
    author='Lululepu',
    author_email='a.no.qsdf@gmail.com'
)  