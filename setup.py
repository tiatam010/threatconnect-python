from distutils.core import setup

setup(
    name='threatconnect-python',
    version='2.9beta',
    packages=['threatconnect', 'threatconnect/Config', 'threatconnect/Properties', 'threatconnect/Resources'],
    url='https://github.com/ThreatConnect-Inc/threatconnect-python',
    license='GPLv3',
    author='ThreatConnect',
    author_email='support@threatconnect.com',
    description='Python wrapper for ThreatConnect API',
    install_requires=['requests', 'enum34', 'python-dateutil']
)
