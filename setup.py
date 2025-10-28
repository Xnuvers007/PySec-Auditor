from setuptools import setup, find_packages
setup(
    name="pysec_auditor",
    version="10.0.0",
    description="PySec Auditor - HTTP & TLS defensive auditing toolkit",
    author="Sardidev",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "requests", "beautifulsoup4", "pyfiglet", "rich"
    ],
    python_requires=">=3.9",
)
