from setuptools import setup, find_packages

setup(
    name='ungrabber',
    version='0.0.6',
    license='MIT',
    description='Ungrabber is a python module to automatically decompile and get the C2/Type of almost every known python grabbers',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    entry_points={
        "console_scripts": [
            "ungrab=Ungrabber.cli:ungrab",
        ],
    },
    install_requires=['xdis', 'cryptography', 'pycryptodome', 'yara-python'],
    include_package_data=True,
    url='https://github.com/lululepu/Ungrabber',
    author='Lululepu',
    author_email='a.no.qsdf@gmail.com'
)  