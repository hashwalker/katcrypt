from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="katcrypt",
    version="0.1.0",
    author="hashwalker",
    author_email="hashwalker125@protonmail.com",
    description="A pure Python encryption library supporting a variety of algorithms and modes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hashwalker/katcrypt",
    packages=find_packages(),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.7",
    keywords="cryptography, encryption, aes, mars, threefish, block cipher, security, crypto",
    project_urls={
        "Source": "https://github.com/hashwalker/katcrypt",
        "Documentation": "https://github.com/hashwalker/katcrypt#readme",
    },
    install_requires=[
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov",
        ],
    },
)