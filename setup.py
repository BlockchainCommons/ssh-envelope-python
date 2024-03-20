from setuptools import setup, find_packages

setup(
    name='ssh_envelope',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'ssh_envelope = ssh_envelope.main:main'
        ]
    },
    install_requires=[
    ],
    # Other setup configuration...
)
