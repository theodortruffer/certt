from setuptools import setup

setup(
    name='certt',
    version='0.1.0',
    py_modules=['certt', 'utilities', 'bcolors'],
    entry_points={
        'console_scripts': [
            'certt = certt:cli',
        ]
    }
)