"""The setup module for django_saml2_auth.
See:
https://github.com/loadimpact/django_saml2_auth
"""

from codecs import open
from setuptools import (setup, find_packages)
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="django_saml2_auth",

    version="3.0.0",

    description="Django SAML2 Authentication Made Easy.",
    long_description=long_description,

    url="https://github.com/loadimpact/django-saml2-auth",

    author="Fang Li",
    author_email="surivlee+djsaml2auth@gmail.com",

    maintainer="Mostafa Moradian",
    maintainer_email="mostafa@k6.io",

    license="Apache 2.0",

    classifiers=[
        "Development Status :: 5 - Production/Stable",

        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",

        "License :: OSI Approved :: Apache Software License",

        "Framework :: Django :: 1.7",
        "Framework :: Django :: 1.8",
        "Framework :: Django :: 1.9",
        "Framework :: Django :: 1.10",
        "Framework :: Django :: 2.1",
        "Framework :: Django :: 2.2",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],

    keywords=[
        "django",
        "saml",
        "saml2"
        "sso",
        "authentication",
        "okta",
        "standard"
    ],

    packages=find_packages(),

    install_requires=["pysaml2==6.4.1",
                      "PyJWT==2.0.1",
                      "dictor==0.1.7"],
    include_package_data=True,
)
