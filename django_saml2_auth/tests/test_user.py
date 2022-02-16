from typing import Any, Dict

import pytest
from django.contrib.auth.models import Group
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.user import (create_jwt_token, create_new_user,
                                    decode_jwt_token, get_or_create_user,
                                    get_user, get_user_id)
from jwt.exceptions import PyJWTError
from pytest_django.fixtures import SettingsWrapper


private_key = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,098DF8240D954EE0

uW/IYor+xm5vOLHhDovanTaYWf+N/f+Yae80KJyuXaJ45jVtZBmbhQKy6MIc3pHG
QICO4x8esHkOgkzicnjGjaWscTIEy6yZzOzAGsA8t4uLTKix9TM31QQnaUVVWXtn
mSJN6rY3Qdudgzss47qcFjS+Rhr+X+u8PB3FhOd6Tgkphpl5Vdkb2K+bcbaXuUlN
DUUigoR0+7N5wCJHGKKQd6YRDKvSC4yo0VHbN3Hb55+84m1MGE+pPU8krkmL0u3M
7b37nOVXq+4bE/2t0UIVwZyz+pAqAC3tRpSKfe8EN/R2VcfRi4QNrtAkLxYaLWCr
SpQA7/qLuEXH1LeUFvDk/SjmCBvNz5vm8hSrj0O5eXN4uIBTg7tdof4KOxozaYKM
4SSnfEWjwDwGr/fE6Om5wKrwUjOm3ZTkOHEz5AarVFOsrccLFxSl7+RRKCeIlHSl
uAmqBW6pVxS65fwCwocHJ0jVKxEKGz3j++aqmQ0omEhtGWcDcfQMP6sAV1tY/FDd
NkVTD/cv23SeHZtjtCxz0W8/Vsqs6U6HMLTb0uJVVdMBiPnTYPKOeACx6GxnwH/e
VrjKEy9xqxzdo59lExl06ZBLd9x9u2CAhLqUIlqQu4EtGStpcDuEHj8LY7Y2Jt/G
w2IGG72YXrrewCFjgYcvsIjbwnFy/FeDyd5dLK4iT6bzInEm3Eo6MZYImBmD9gkB
4U8rXXQwXPwPM+rKwRlbP9v+k5Af29Br6L1T+MAczjThlIdikuCvFoRLQ921De83
iFL0LKtbK1sAtmnQBdTYRyWz0MDLJ+7emcXO/NEuK8EogQrLX0wyNXsH3bmXZXzk
sBI8gK80e/4hRYdHqgmU8XTI4PTa3tj29hpZa57nG6Ccd2uUULjBiUOBIe6Tm72D
DMGqY0wQWOn+wMPLBedOGyJdTWJvDlPpiuboCrr8ughkYIt/d6XynKdejCescJLM
t4pwG058EL489Y8O6UAtQYxuj2jrLx7aLxdWxBFjWmKdoDs/p7tOiOcOt6byXybE
xpoPG+h9X/GkoH8PaEqL40JlsNcb8dcaUcw2bBUjALnQ38eYETeoUFIsIhZ6nwtq
NzJlsWwHtaFue8Eh8/SxQ1ctU5U52E7pNm8vTNmjj1wVgSqht1RSfM/L5WyoqLrO
RZTUSqqrDGE31mwpPtEPPUyoGnBroMpJLGoYi03UIn/eSM87gCLBb1Wcsc+BarPf
KSSaCE+F3tpIssN1li5nYnfBtVd1hG6f8iCrZo+Ch+N1EVrYFuFSpUTUNSAZiwD2
hoRVxyVtDsvIZ+rasbcYSQZyPwhGB6vqjhwdJMIQ6nPyeWZYwPp18alcWRv/UIR7
SnEm4NBDCLAXnil2PxCw2c832yTI5/vv8Mi4UvunrUDk2C1ikcwPsPZFMhGYdUxJ
O0QirCOeIhRTTsSWxRx5Ac4BOdFjr+Hj8kQd9y/LGdeZ9XjB2AYirTj6zLZynJNa
cZU/c743apbLxvv6tvkzcM8hI1pYoYBZ+Eu5aSUqKZaUXxgARKnDX99GUVAXutAG
yjwNaiZe1gCKjP7aKZ85+uJZkRvlK/eB/EiNXyhKriKs/vraMeOgtA==
-----END RSA PRIVATE KEY-----"""

passphrase = "123456"

unencrypted_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA5EBnGco/VgirZAUk1qtPR1pkgEMdqBZImTPp6Xf4MDhB7zev
veqlXAdaFcvrG4rdO4jHr5snJzJpY52en27a/z2gtQhR9f/05ZjpX9eKCpNt8c/2
SDf/P+omEbvbvoUSjkyGeWBacRuHHj6C1voUrl1aKokRfV9GaSkN7+lOxCBCjXFn
xEsLlbJZFSsAQPf1282v5SuE2FxMjbs/Xrmjl1Q3h8YsV+vvrRK6/OczPVUb6M4H
KHqIpH5UTjP/44Mr5sbanjEEYCOsxiM7Q8JUEYczyjn/o2j8/w0Lms8LB8tnVpxd
pwp7QoPVRIr1slYlilP/fL6ZzL5k87XUsi4yGwIDAQABAoIBAASCnUbuLyg1DaXx
UBQJ2IwxZhD+woRCxHZ6hyG85COXyP3AHPHkxBW4c3hAykmGCe8WOdPnffORVHHK
eIrv9tXaUuWg33W79AvhZKMnMCwbU63WjShKKvoJV208SBBQstgq/PFDDSZ1A8t+
MrmqwWPcpl52zOisTEjhrcvS0WKgswFHqveaM4Ss1tR+VNj93r+lKXjsKrUfB1+b
T/+9aEjsGiKtfZ+EtUGyanoI/FnVs45ieUeb+WX8x9fJPXyLGeEWSlBQ8RdT1R00
VnYY37P+M8ITzwpQzosViClfSPk8ljTkhT+EdictTYVXMCKGUTQOTdw5SRH5l90L
YPFS7KECgYEA+QFhPNLWQEcIhEJT5q9Rh73u/jDW76f6UfrxIA59tOtlFPpYvYne
P2BPGbDPpdCIf6ypgGITuKjGhd6WbPIrRZz0g1iijlV5nfD+/fzj1ACTMBkBNHd+
1ysHjwlRPqJIFB/3Us0BtcYX+4hz1JHA/z7OBbEwKeIZ6uGcN0xw1vECgYEA6qnH
xErGnHsSTlVHg6k68RQzeiN/8tWAIGcp4QhlC6p5TeN+X8d25pUuWENNcZZNbC5M
hlz8dQ52aB8kVxZkRSOinraUtNoMnVriR3hr4iS9gMVGA+HQR3S5IdnBVnleRUfl
qDM/MxL3Ru0sYp4Fr2ndw4aJPUIVyAeTMVLJ0csCgYEA1KrWBqG3tRw17OfNSrev
tXSFevnxiKv5wizF5fAacvuc0GbkhbULaStzQ2jcYC0Td5/bALhDSbJ0I3+xEAlg
5cqgltGLvG7KORfMYNatKrL3AtxISCxK27B3ezWk+w6U6wNGM6S98ibm8sBe1U1K
/XUBdqEXlp3yLsZTqnMR6LECgYBRrl9WuCCB/2TT12NZNOLLX5i7fvfecupyXPZ6
2g0yDljC/9jRRgDhKjRDjMm8K/EvIr6IVn2Z0Trt60ke9zBX0JueWzdP7EZPz37M
GeKTiO5dkE1atJNnC/4VBlMB4qUpwGj0L0JkaMmh6pR0j0SzVkpW8NF8fTBPvDNE
C+ksGQKBgDvsvOc/8OfDVvu3OgUJnACQdKUD56ppYUZ8XLo34vUm2JAXeb5nRAdZ
Fo4X5nN+G7W2lV5W5384zfjN3IREeZtg4ZKw0w+vJrhz6bixBIOfMCu0O9TYT11B
G2RcH+T0kcs7QbXTY4QrMEYYQj4viihDDo3Ndt5eNJKPz2s+F2h3
-----END RSA PRIVATE KEY-----"""

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5EBnGco/VgirZAUk1qtP
R1pkgEMdqBZImTPp6Xf4MDhB7zevveqlXAdaFcvrG4rdO4jHr5snJzJpY52en27a
/z2gtQhR9f/05ZjpX9eKCpNt8c/2SDf/P+omEbvbvoUSjkyGeWBacRuHHj6C1voU
rl1aKokRfV9GaSkN7+lOxCBCjXFnxEsLlbJZFSsAQPf1282v5SuE2FxMjbs/Xrmj
l1Q3h8YsV+vvrRK6/OczPVUb6M4HKHqIpH5UTjP/44Mr5sbanjEEYCOsxiM7Q8JU
EYczyjn/o2j8/w0Lms8LB8tnVpxdpwp7QoPVRIr1slYlilP/fL6ZzL5k87XUsi4y
GwIDAQAB
-----END PUBLIC KEY-----"""


def trigger_change_first_name(user: Dict[str, Any]) -> None:
    """Trigger function to change user's first name.

    Args:
        user (Dict[str, Any]): User information
    """
    user = get_user(user)
    user.first_name = "CHANGED_FIRSTNAME"
    user.save()


@pytest.mark.django_db
def test_create_new_user_success(settings: SettingsWrapper):
    """Test create_new_user function to verify if it works and correctly joins the user to the
    respective group.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "NEW_USER_PROFILE": {
            "USER_GROUPS": ["users"],
        }
    }

    # Create a group for the users to join
    Group.objects.create(name="users")
    user = create_new_user("test@example.com", "John", "Doe")
    # It can also be email depending on USERNAME_FIELD setting
    assert user.username == "test@example.com"
    assert user.is_active == True
    assert user.has_usable_password() == False
    assert user.groups.get(name="users") == Group.objects.get(name="users")


@pytest.mark.django_db
def test_create_new_user_no_group_error(settings: SettingsWrapper):
    """Test create_new_user function to verify if it creates the user, but fails to join the user
    to the respective group.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "NEW_USER_PROFILE": {
            "USER_GROUPS": ["users"],
        }
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        create_new_user("test@example.com", "John", "Doe")

    assert str(exc_info.value) == "There was an error joining the user to the group."
    assert exc_info.value.extra["exc_type"] == Group.DoesNotExist


def test_create_new_user_value_error():
    """Test create_new_user function to verify if it raises an exception upon passing invalid value
    as user_id."""
    with pytest.raises(SAMLAuthError) as exc_info:
        create_new_user("", "John", "Doe")

    assert str(exc_info.value) == "There was an error creating the new user."
    assert exc_info.value.extra["exc_type"] == ValueError


@pytest.mark.django_db
def test_get_or_create_user_success(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it creates a new user and joins it to the
    correct group based on the given SAML group and its mapping with internal groups.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "ATTRIBUTES_MAP": {
            "groups": "groups",
        },
        "GROUPS_MAP": {
            "consumers": "users"
        }
    }

    Group.objects.create(name="users")
    created, user = get_or_create_user({
        "username": "test@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "user_identity": {
            "user.username": "test@example.com",
            "user.first_name": "John",
            "user.last_name": "Doe",
            "groups": ["consumers"]
        }
    })
    assert created
    assert user.username == "test@example.com"
    assert user.is_active == True
    assert user.has_usable_password() == False
    assert user.groups.get(name="users") == Group.objects.get(name="users")


@pytest.mark.django_db
def test_get_or_create_user_trigger_error(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it raises an exception in case the CREATE_USER
    trigger function is nonexistent.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "TRIGGER": {
            "CREATE_USER": "django_saml2_auth.tests.test_user.nonexistent_trigger",
        }
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        get_or_create_user({
            "username": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        })

    assert str(exc_info.value) == (
        "module 'django_saml2_auth.tests.test_user' has no attribute 'nonexistent_trigger'")
    assert isinstance(exc_info.value.extra["exc"], AttributeError)


@pytest.mark.django_db
def test_get_or_create_user_trigger_change_first_name(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it correctly triggers the CREATE_USER function
    and the trigger updates the user's first name.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "TRIGGER": {
            "CREATE_USER": "django_saml2_auth.tests.test_user.trigger_change_first_name",
        }
    }

    created, user = get_or_create_user({
        "username": "test@example.com",
        "first_name": "John",
        "last_name": "Doe"
    })

    assert created
    assert user.username == "test@example.com"
    assert user.first_name == "CHANGED_FIRSTNAME"
    assert user.is_active == True
    assert user.has_usable_password() == False


@pytest.mark.django_db
def test_get_or_create_user_should_not_create_user(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it raise an exception while creating a new user
    is prohibited by settings.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "CREATE_USER": False,
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        get_or_create_user({
            "username": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        })

    assert str(exc_info.value) == "Cannot create user."
    assert exc_info.value.extra["reason"] == (
        "Due to current config, a new user should not be created.")


def test_get_user_id_success():
    """Test get_user_id function to verify if it correctly returns the user_id based on the
    User.USERNAME_FIELD."""
    assert get_user_id({"username": "test@example.com"}) == "test@example.com"
    assert get_user_id("test@example.com") == "test@example.com"


@pytest.mark.django_db
def test_get_user_success():
    """Test get_user function by first creating a new user and then trying to fetch it."""
    create_new_user("test@example.com", "John", "Doe")
    user_1 = get_user({"username": "test@example.com"})
    user_2 = get_user("test@example.com")

    assert user_1.username == "test@example.com"
    assert user_2.username == "test@example.com"
    assert user_1 == user_2


@pytest.mark.parametrize("saml2_settings", [
    {
        "JWT_ALGORITHM": "HS256",
        "JWT_SECRET": "secret"
    },
    {
        "JWT_ALGORITHM": "RS256",
        "JWT_PRIVATE_KEY": private_key,
        "JWT_PRIVATE_KEY_PASSPHRASE": passphrase,
        "JWT_PUBLIC_KEY": public_key},
    {
        "JWT_ALGORITHM": "RS256",
        "JWT_PRIVATE_KEY": unencrypted_private_key,
        "JWT_PUBLIC_KEY": public_key},
])
def test_create_and_decode_jwt_token_success(
        settings: SettingsWrapper, saml2_settings: Dict[str, Any]):
    """Test create_jwt_token and decode_jwt_token functions by verifying if the newly created
    JWT token using is valid.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        saml2_settings (Dict[str, Any]): Fixture for SAML2 settings
    """
    settings.SAML2_AUTH = saml2_settings

    jwt_token = create_jwt_token("test@example.com")
    user_id = decode_jwt_token(jwt_token)
    assert user_id == "test@example.com"


@pytest.mark.parametrize('saml2_settings,error_msg', [
    ({
        "JWT_ALGORITHM": None
    }, "Cannot encode/decode JWT token. Specify an algorithm."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_SECRET": None
    }, "Cannot encode/decode JWT token. Specify a secret."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_SECRET": "",
    }, "Cannot encode/decode JWT token. Specify a secret."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_PRIVATE_KEY": "-- PRIVATE KEY --"
    }, "Cannot encode/decode JWT token. Specify a secret."),
    ({
        "JWT_ALGORITHM": "RS256",
    }, "Cannot encode/decode JWT token. Specify a private key."),
    ({
        "JWT_ALGORITHM": "RS256",
        "JWT_SECRET": "A_SECRET_PHRASE"
    }, "Cannot encode/decode JWT token. Specify a private key."),
])
def test_create_jwt_token_with_incorrect_jwt_settings(
        settings: SettingsWrapper, saml2_settings: Dict[str, str], error_msg: str):
    """Test create_jwt_token function by trying to create a JWT token with incorrect settings.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        saml2_settings (Dict[str, str]): Fixture for SAML2 settings
        error_msg (str): Expected error message
    """
    settings.SAML2_AUTH = saml2_settings

    with pytest.raises(SAMLAuthError) as exc_info:
        create_jwt_token("test@example.com")

    assert str(exc_info.value) == error_msg


@pytest.mark.parametrize('saml2_settings,error_msg', [
    ({
        "JWT_ALGORITHM": None
    }, "Cannot encode/decode JWT token. Specify an algorithm."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_SECRET": None
    }, "Cannot encode/decode JWT token. Specify a secret."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_SECRET": "",
    }, "Cannot encode/decode JWT token. Specify a secret."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_PRIVATE_KEY": "-- PRIVATE KEY --"
    }, "Cannot encode/decode JWT token. Specify a secret."),
    ({
        "JWT_ALGORITHM": "HS256",
        "JWT_SECRET": "secret",
        "JWT_EXP": -60
    }, "Cannot decode JWT token."),
    ({
        "JWT_ALGORITHM": "RS256",
    }, "Cannot encode/decode JWT token. Specify a public key."),
    ({
        "JWT_ALGORITHM": "RS256",
        "JWT_SECRET": "A_SECRET_PHRASE"
    }, "Cannot encode/decode JWT token. Specify a public key.",),
])
def test_decode_jwt_token_with_incorrect_jwt_settings(
        settings: SettingsWrapper, saml2_settings: Dict[str, str], error_msg: str):
    """Test decode_jwt_token function by trying to create a JWT token with incorrect settings.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        saml2_settings (Dict[str, str]): Fixture for SAML2 settings
        error_msg (str): Expected error message
    """
    settings.SAML2_AUTH = saml2_settings

    with pytest.raises(SAMLAuthError) as exc_info:
        decode_jwt_token("WHATEVER")

    assert str(exc_info.value) == error_msg


def test_decode_jwt_token_failure():
    """Test decode_jwt_token function by passing an invalid JWT token (None, in this case)."""
    with pytest.raises(SAMLAuthError) as exc_info:
        decode_jwt_token(None)

    assert str(exc_info.value) == "Cannot decode JWT token."
    assert isinstance(exc_info.value.extra["exc"], PyJWTError)
