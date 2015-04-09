from distutils.core import setup

setup(
    name='threatconnect-python',
    version='2.9beta',
    packages=['threatconnect'],
    url='https://github.com/ThreatConnect-Inc/threatconnect-python',
    license='GPLv3',
    author='ThreatConnect',
    author_email='support@threatconnect.com',
    description='Python wrapper for ThreatConnect API',
    requires=['requests', 'enum34', 'python-dateutil']
)
