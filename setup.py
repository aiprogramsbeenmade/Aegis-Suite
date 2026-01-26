from setuptools import setup, find_packages

setup(
    name="aegis-suite",
    version="1.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "cryptography",
        "colorama",
        "pillow",
        "python-dotenv",
    ],
    entry_points={
        'console_scripts': [
            'aegis=main:main', # Chiama la funzione main() nel file main.py
        ],
    },
)