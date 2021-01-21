from typing import Optional, List, Mapping

import pytest
import responses
from django.http import HttpRequest
from django.test.client import RequestFactory
from django.urls import NoReverseMatch
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.saml import (decode_saml_response,
                                    extract_user_identity, get_assertion_url,
                                    get_default_next_url, get_metadata,
                                    get_saml_client, validate_metadata_url)
from django_saml2_auth.views import acs
from pytest_django.fixtures import SettingsWrapper
from saml2.client import Saml2Client
from saml2.response import AuthnResponse

GET_METADATA_AUTO_CONF_URLS = "django_saml2_auth.tests.test_saml.get_metadata_auto_conf_urls"
METADATA_URL1 = "https://testserver1.com/saml/sso/metadata"
METADATA_URL2 = "https://testserver2.com/saml/sso/metadata"
# Ref: https://en.wikipedia.org/wiki/SAML_metadata#Entity_metadata
METADATA1 = b"""
<md:EntityDescriptor entityID="https://testserver1.com/entity" validUntil="2025-08-30T19:10:29Z"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:METADATA1"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:mdrpi="urn:oasis:names:tc:SAML:METADATA1:rpi"
    xmlns:mdattr="urn:oasis:names:tc:SAML:METADATA1:attribute"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- insert ds:Signature element (omitted) -->
    <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="https://testserver1.com/"/>
    <mdrpi:PublicationInfo creationInstant="2025-08-16T19:10:29Z" publisher="https://testserver1.com/"/>
    <mdattr:EntityAttributes>
        <saml:Attribute Name="https://testserver1.com/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>https://testserver1.com/category/self-certified</saml:AttributeValue>
        </saml:Attribute>
    </mdattr:EntityAttributes>
    </md:Extensions>
    <!-- insert one or more concrete instances of the md:RoleDescriptor abstract type (see below) -->
    <md:Organization>
    <md:OrganizationName xml:lang="en">...</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">...</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://testserver1.com/</md:OrganizationURL>
    </md:Organization>
    <md:ContactPerson contactType="technical">
    <md:SurName>SAML Technical Support</md:SurName>
    <md:EmailAddress>mailto:technical-support@example.info</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>"""
METADATA2 = b"""
<md:EntityDescriptor entityID="https://testserver2.com/entity" validUntil="2025-08-30T19:10:29Z"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:METADATA1"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:mdrpi="urn:oasis:names:tc:SAML:METADATA1:rpi"
    xmlns:mdattr="urn:oasis:names:tc:SAML:METADATA1:attribute"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- insert ds:Signature element (omitted) -->
    <md:Extensions>
    <mdrpi:RegistrationInfo registrationAuthority="https://testserver2.com/"/>
    <mdrpi:PublicationInfo creationInstant="2025-08-16T19:10:29Z" publisher="https://testserver2.com/"/>
    <mdattr:EntityAttributes>
        <saml:Attribute Name="https://testserver2.com/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>https://testserver2.com/category/self-certified</saml:AttributeValue>
        </saml:Attribute>
    </mdattr:EntityAttributes>
    </md:Extensions>
    <!-- insert one or more concrete instances of the md:RoleDescriptor abstract type (see below) -->
    <md:Organization>
    <md:OrganizationName xml:lang="en">...</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">...</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://testserver2.com/</md:OrganizationURL>
    </md:Organization>
    <md:ContactPerson contactType="technical">
    <md:SurName>SAML Technical Support</md:SurName>
    <md:EmailAddress>mailto:technical-support@example.info</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>"""


def get_metadata_auto_conf_urls(user_id: Optional[str] = None) -> List[Optional[Mapping[str, str]]]:
    """Fixture for returning metadata autoconf URL(s) based on the user_id.

    Args:
        user_id (str, optional): User identifier: username or email. Defaults to None.

    Returns:
        list: Either an empty list or a list of valid metadata URL(s)
    """
    if user_id == "nonexistent_user@example.com":
        return []
    if user_id == "test@example.com":
        return [{"url": METADATA_URL1}]
    return [{"url": METADATA_URL1}, {"url": METADATA_URL2}]


def get_user_identity() -> Mapping[str, List[str]]:
    """Fixture for returning user identity produced by pysaml2.

    Returns:
        dict: keys are SAML attributes and values are lists of attribute values
    """
    return {
        "user.username": ["test@example.com"],
        "user.email": ["test@example.com"],
        "user.first_name": ["John"],
        "user.last_name": ["Doe"],
        "token": ["TOKEN"]
    }


def mock_parse_authn_request_response(
        self: Saml2Client, response: AuthnResponse, binding: str) -> "MockAuthnResponse":
    """Mock function to return an mocked instance of AuthnResponse.

    Returns:
        MockAuthnResponse: A mocked instance of AuthnResponse
    """
    class MockAuthnRequest:
        name_id = "Username"

        @staticmethod
        def issuer():
            return METADATA_URL1

        @staticmethod
        def get_identity():
            return get_user_identity()

    return MockAuthnRequest()


def test_get_assertion_url_success():
    """Test get_assertion_url function to verify if it correctly returns the default assertion URL.
    """
    assertion_url = get_assertion_url(HttpRequest())
    assert assertion_url == "https://api.example.com"


def test_get_assertion_url_no_assertion_url(settings: SettingsWrapper):
    """Test get_assertion_url function to verify if it correctly returns the server's assertion URL
    based on the incoming request.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["ASSERTION_URL"] = None
    get_request = RequestFactory().get("/acs/")
    assertion_url = get_assertion_url(get_request)
    assert assertion_url == "http://testserver"


def test_get_default_next_url_success():
    """Test get_default_next_url to verify if it returns the correct default next URL."""
    default_next_url = get_default_next_url()
    assert default_next_url == "http://app.example.com/account/login"


def test_get_default_next_url_no_default_next_url(settings: SettingsWrapper):
    """Test get_default_next_url function with no default next url for redirection to see if it
    returns the admin:index route.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["DEFAULT_NEXT_URL"] = None
    with pytest.raises(SAMLAuthError) as exc_info:
        get_default_next_url()

    # This doesn't happen on a real instance, unless you don't have "admin:index" route
    assert str(exc_info.value) == "We got a URL reverse issue: ['admin:index']"
    assert issubclass(exc_info.value.extra["exc_type"], NoReverseMatch)


@responses.activate
def test_validate_metadata_url_success():
    """Test validate_metadata_url function to verify a valid metadata URL."""
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)
    result = validate_metadata_url(METADATA_URL1)
    assert result


@responses.activate
def test_validate_metadata_url_failure():
    """Test validate_metadata_url function to verify if it correctly identifies an invalid metadata
    URL."""
    responses.add(responses.GET, METADATA_URL1)
    result = validate_metadata_url(METADATA_URL1)
    assert result == False


@responses.activate
def test_get_metadata_success_with_single_metadata_url(settings: SettingsWrapper):
    """Test get_metadata function to verify if it returns a valid metadata URL with a correct
    format.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["METADATA_AUTO_CONF_URL"] = METADATA_URL1
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = None
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)

    result = get_metadata()
    assert result == {"remote": [{"url": METADATA_URL1}]}


def test_get_metadata_failure_with_invalid_metadata_url(settings: SettingsWrapper):
    """Test get_metadata function to verify if it fails with invalid metadata information.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    # HTTP Responses are not mocked, so this will fail.
    settings.SAML2_AUTH["METADATA_AUTO_CONF_URL"] = METADATA_URL1
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = None

    with pytest.raises(SAMLAuthError) as exc_info:
        get_metadata()

    assert str(exc_info.value) == "Invalid metadata URL."


@responses.activate
def test_get_metadata_success_with_multiple_metadata_urls(settings: SettingsWrapper):
    """Test get_metadata function to verify if it returns multiple metadata URLs if the user_id is
    unknown.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = GET_METADATA_AUTO_CONF_URLS
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)
    responses.add(responses.GET, METADATA_URL2, body=METADATA2)

    result = get_metadata()
    assert result == {"remote": [{"url": METADATA_URL1}, {"url": METADATA_URL2}]}


@responses.activate
def test_get_metadata_success_with_user_id(settings: SettingsWrapper):
    """Test get_metadata function to verify if it returns a valid metadata URLs given the user_id.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = GET_METADATA_AUTO_CONF_URLS
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)

    result = get_metadata("test@example.com")
    assert result == {"remote": [{"url": METADATA_URL1}]}


def test_get_metadata_failure_with_nonexistent_user_id(settings: SettingsWrapper):
    """Test get_metadata function to verify if it raises an exception given a nonexistent user_id.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = GET_METADATA_AUTO_CONF_URLS

    with pytest.raises(SAMLAuthError) as exc_info:
        get_metadata("nonexistent_user@example.com")
    assert str(exc_info.value) == "No metadata URL associated with the given user identifier."


def test_get_metadata_success_with_local_file(settings: SettingsWrapper):
    """Test get_metadata function to verify if correctly returns path to local metadata file.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = None
    settings.SAML2_AUTH["METADATA_LOCAL_FILE_PATH"] = "/absolute/path/to/metadata.xml"

    result = get_metadata()
    assert result == {"local": ["/absolute/path/to/metadata.xml"]}


def test_get_saml_client_success(settings: SettingsWrapper):
    """Test get_saml_client function to verify if it is correctly instantiated with local metadata
    file.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["METADATA_LOCAL_FILE_PATH"] = "django_saml2_auth/tests/metadata.xml"
    result = get_saml_client("example.com", acs)
    assert isinstance(result, Saml2Client)


@responses.activate
def test_get_saml_client_success_with_user_id(settings: SettingsWrapper):
    """Test get_saml_client function to verify if it is correctly instantiated with remote metadata
    URL and valid user_id.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = GET_METADATA_AUTO_CONF_URLS
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)

    result = get_saml_client("example.com", acs, "test@example.com")
    assert isinstance(result, Saml2Client)


def test_get_saml_client_failure_with_missing_metadata_url(settings: SettingsWrapper):
    """Test get_saml_client function to verify if it raises an exception given a missing non-mocked
    metadata URL.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = GET_METADATA_AUTO_CONF_URLS

    with pytest.raises(SAMLAuthError) as exc_info:
        get_saml_client("example.com", acs, "test@example.com")

    assert str(exc_info.value) == "Metadata URL/file is missing."


def test_get_saml_client_failure_with_invalid_file(settings: SettingsWrapper):
    """Test get_saml_client function to verify if it raises an exception given an invalid path to
    metadata file.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH["METADATA_LOCAL_FILE_PATH"] = "/invalid/metadata.xml"
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = None

    with pytest.raises(SAMLAuthError) as exc_info:
        get_saml_client("example.com", acs)

    assert str(exc_info.value) == "[Errno 2] No such file or directory: '/invalid/metadata.xml'"
    assert isinstance(exc_info.value.extra["exc"], FileNotFoundError)


@responses.activate
def test_decode_saml_response_success(settings: SettingsWrapper, monkeypatch: "MonkeyPatch"):
    """Test decode_saml_response function to verify if it correctly decodes the SAML response.

    Args:
        settings (SettingsWrapper): Fixture for django settings
        monkeypatch (MonkeyPatch): PyTest monkeypatch fixture
    """
    responses.add(responses.GET, METADATA_URL1, body=METADATA1)
    settings.SAML2_AUTH["ASSERTION_URL"] = "https://api.example.com"
    settings.SAML2_AUTH["TRIGGER"]["GET_METADATA_AUTO_CONF_URLS"] = GET_METADATA_AUTO_CONF_URLS

    post_request = RequestFactory().post(METADATA_URL1, {"SAMLResponse": "SAML RESPONSE"})
    monkeypatch.setattr(Saml2Client,
                        "parse_authn_request_response",
                        mock_parse_authn_request_response)
    result = decode_saml_response(post_request, acs)
    assert len(result.get_identity()) > 0


def test_extract_user_identity_success():
    """Test extract_user_identity function to verify if it correctly extracts user identity
    information from a (pysaml2) parsed SAML response."""
    result = extract_user_identity(get_user_identity())
    assert len(result) == 6
    assert result["username"] == result["email"] == "test@example.com"
    assert result["first_name"] == "John"
    assert result["last_name"] == "Doe"
    assert result["token"] == "TOKEN"
    assert result["user_identity"] == get_user_identity()
