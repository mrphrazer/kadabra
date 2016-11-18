from distutils.core import setup

setup(
    name='kadabra',
    version='',
    packages=['kadabra', 'kadabra.arch', 'kadabra.arch.x86', 'kadabra.loader', 'kadabra.loader.elf',
              'kadabra.emulator', 'kadabra.utils'],
    url='https://github.com/mrphrazer/kadabra',
    license='GPLv2',
    author='Tim Blazytko',
    author_email='mr.phrazer@gmail.com',
    description='A blanked execution engine based on the Unicorn engine'
)
