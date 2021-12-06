"""Utility functions for various SAML client functions.
"""

from typing import Any, Callable, Dict, Mapping, Optional, Union

from dictor import dictor
from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import NoReverseMatch
from django_saml2_auth.errors import *
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.utils import get_reverse, run_hook
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.httpbase import HTTPBase
from saml2.mdstore import MetaDataExtern
from saml2.response import AuthnResponse


def get_assertion_url(request: HttpRequest) -> str:
    """Extract protocol and domain name from request, if ASSERTION_URL is not specified in settings,
    otherwise the ASSERTION_URL is returned.

    Args:
        request (HttpRequest): Django request object

    Returns:
        str: Either protocol://host or ASSERTION_URL
    """
    assertion_url = settings.SAML2_AUTH.get("ASSERTION_URL")
    if assertion_url:
        return assertion_url

    protocol = "https" if request.is_secure() else "http"
    host = request.get_host()
    return f"{protocol}://{host}"


def get_default_next_url() -> Optional[str]:
    """Get default next url for redirection, which is either the DEFAULT_NEXT_URL from settings or
    admin index.

    Returns:
        Optional[str]: Returns default next url for redirection or admin index
    """
    default_next_url = settings.SAML2_AUTH.get("DEFAULT_NEXT_URL")
    if default_next_url:
        return default_next_url

    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse("admin:index")


def validate_metadata_url(url: str) -> bool:
    """Validates metadata URL

    Args:
        url (str): Metadata URL

    Returns:
        bool: Wether the metadata URL is valid or not
    """
    try:
        http_client = HTTPBase()
        metadata = MetaDataExtern(None, url=url, http=http_client)
        metadata.load()
    except:
        return False

    return True


def get_metadata(user_id: Optional[str] = None) -> Mapping[str, Any]:
    """Returns metadata information, either by running the GET_METADATA_AUTO_CONF_URLS hook function
    if available, or by checking and returning a local file path or the METADATA_AUTO_CONF_URL. URLs
    are always validated and invalid URLs will be either filtered or raise a SAMLAuthError
    exception.

    Args:
        user_id (str, optional): If passed, it will be further processed by the
            GET_METADATA_AUTO_CONF_URLS trigger, which will return the metadata URL corresponding to
            the given user identifier, either email or username. Defaults to None.

    Raises:
        SAMLAuthError: No metadata URL associated with the given user identifier.
        SAMLAuthError: Invalid metadata URL.

    Returns:
        Mapping[str, Any]: Returns a SAML metadata object as dictionary
    """
    get_metadata_trigger = dictor(settings.SAML2_AUTH, "TRIGGER.GET_METADATA_AUTO_CONF_URLS")
    if get_metadata_trigger:
        metadata_urls = run_hook(get_metadata_trigger, user_id)
        if metadata_urls:
            # Filter invalid metadata URLs
            filtered_metadata_urls = list(
                filter(lambda md: validate_metadata_url(md["url"]), metadata_urls))
            return {"remote": filtered_metadata_urls}
        else:
            raise SAMLAuthError("No metadata URL associated with the given user identifier.",
                                extra={
                                    "exc_type": ValueError,
                                    "error_code": NO_METADATA_URL_ASSOCIATED,
                                    "reason": "There was an error processing your request.",
                                    "status_code": 500
                                })

    metadata_local_file_path = settings.SAML2_AUTH.get("METADATA_LOCAL_FILE_PATH")
    if metadata_local_file_path:
        return {"local": [metadata_local_file_path]}
    else:
        single_metadata_url = settings.SAML2_AUTH.get("METADATA_AUTO_CONF_URL")
        if validate_metadata_url(single_metadata_url):
            return {"remote": [{"url": single_metadata_url}]}
        else:
            raise SAMLAuthError("Invalid metadata URL.", extra={
                "exc_type": ValueError,
                "error_code": INVALID_METADATA_URL,
                "reason": "There was an error processing your request.",
                "status_code": 500
            })


def get_saml_client(domain: str,
                    acs: Callable[..., HttpResponse],
                    user_id: str = None) -> Optional[Saml2Client]:
    """Create a new Saml2Config object with the given config and return an initialized Saml2Client
    using the config object. The settings are read from django settings key: SAML2_AUTH.

    Args:
        domain (str): Domain name to get SAML config for
        acs (Callable[..., HttpResponse]): The acs endpoint

    Raises:
        SAMLAuthError: Re-raise any exception raised by Saml2Config or Saml2Client

    Returns:
        Optional[Saml2Client]: A Saml2Client or None
    """
    acs_url = domain + get_reverse([acs, "acs", "django_saml2_auth:acs"])
    metadata = get_metadata(user_id)
    if (("local" in metadata and not metadata["local"]) or
            ("remote" in metadata and not metadata["remote"])):
        raise SAMLAuthError("Metadata URL/file is missing.", extra={
            "exc_type": NoReverseMatch,
            "error_code": NO_METADATA_URL_OR_FILE,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    saml_settings = {
        "metadata": metadata,
        "allow_unknown_attributes": True,
        "debug": settings.SAML2_AUTH.get("DEBUG", False),
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                "allow_unsolicited": True,
                "authn_requests_signed": dictor(
                    settings, "SAML2_AUTH.AUTHN_REQUESTS_SIGNED", default=True),
                "logout_requests_signed": dictor(
                    settings, "SAML2_AUTH.LOGOUT_REQUESTS_SIGNED", default=True),
                "want_assertions_signed": dictor(
                    settings, "SAML2_AUTH.WANT_ASSERTIONS_SIGNED", default=True),
                "want_response_signed": dictor(
                    settings, "SAML2_AUTH.WANT_RESPONSE_SIGNED", default=True),
            },
        },
    }

    entity_id = settings.SAML2_AUTH.get("ENTITY_ID")
    if entity_id:
        saml_settings["entityid"] = entity_id

    name_id_format = settings.SAML2_AUTH.get("NAME_ID_FORMAT")
    if name_id_format:
        saml_settings["service"]["sp"]["name_id_format"] = name_id_format

    try:
        sp_config = Saml2Config()
        sp_config.load(saml_settings)
        saml_client = Saml2Client(config=sp_config)
        return saml_client
    except Exception as exc:
        raise SAMLAuthError(str(exc), extra={
            "exc": exc,
            "exc_type": type(exc),
            "error_code": ERROR_CREATING_SAML_CONFIG_OR_CLIENT,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })


def decode_saml_response(
        request: HttpRequest,
        acs: Callable[..., HttpResponse]) -> Union[HttpResponseRedirect, Optional[AuthnResponse]]:
    """Given a request, the authentication response inside the SAML response body is parsed,
    decoded and returned. If there are any issues parsing the request, the identity or the issuer,
    an exception is raised.

    Args:
        request (HttpRequest): Django request object from identity provider (IdP)
        acs (Callable[..., HttpResponse]): The acs endpoint

    Raises:
        SAMLAuthError: There was no response from SAML client.
        SAMLAuthError: There was no response from SAML identity provider.
        SAMLAuthError: No name_id in SAML response.
        SAMLAuthError: No issuer/entity_id in SAML response.
        SAMLAuthError: No user identity in SAML response.

    Returns:
        Union[HttpResponseRedirect, Optional[AuthnResponse]]: Returns an AuthnResponse object for
        extracting user identity from.
    """
    saml_client = get_saml_client(get_assertion_url(request), acs)
    if not saml_client:
        raise SAMLAuthError("There was an error creating the SAML client.", extra={
            "exc_type": ValueError,
            "error_code": NO_SAML_CLIENT,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    response = request.POST.get("SAMLResponse") or None
    if not response:
        raise SAMLAuthError("There was no response from SAML client.", extra={
            "exc_type": ValueError,
            "error_code": NO_SAML_RESPONSE_FROM_CLIENT,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    authn_response = saml_client.parse_authn_request_response(response, entity.BINDING_HTTP_POST)
    if not authn_response:
        raise SAMLAuthError("There was no response from SAML identity provider.", extra={
            "exc_type": ValueError,
            "error_code": NO_SAML_RESPONSE_FROM_IDP,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    if not authn_response.name_id:
        raise SAMLAuthError("No name_id in SAML response.", extra={
            "exc_type": ValueError,
            "error_code": NO_NAME_ID_IN_SAML_RESPONSE,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    if not authn_response.issuer():
        raise SAMLAuthError("No issuer/entity_id in SAML response.", extra={
            "exc_type": ValueError,
            "error_code": NO_ISSUER_IN_SAML_RESPONSE,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    if not authn_response.get_identity():
        raise SAMLAuthError("No user identity in SAML response.", extra={
            "exc_type": ValueError,
            "error_code": NO_USER_IDENTITY_IN_SAML_RESPONSE,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    return authn_response


def extract_user_identity(user_identity: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    """Extract user information from SAML user identity object

    Args:
        user_identity (Dict[str, Any]): SAML user identity object (dict)

    Raises:
        SAMLAuthError: No token specified.
        SAMLAuthError: No username or email provided.

    Returns:
        Dict[str, Optional[Any]]: Cleaned user information plus user_identity
            for backwards compatibility
    """
    saml2_auth_settings = settings.SAML2_AUTH
    email_field = dictor(saml2_auth_settings, "ATTRIBUTES_MAP.email", default="user.email")
    username_field = dictor(saml2_auth_settings, "ATTRIBUTES_MAP.username", default="user.username")
    firstname_field = dictor(saml2_auth_settings, "ATTRIBUTES_MAP.first_name", default="user.first_name")
    lastname_field = dictor(saml2_auth_settings, "ATTRIBUTES_MAP.last_name", default="user.last_name")
    token_field = dictor(saml2_auth_settings, "ATTRIBUTES_MAP.token", default="token")

    user = {}
    user["email"] = dictor(user_identity, f"{email_field}/0", pathsep="/")  # Path includes "."
    user["username"] = dictor(user_identity, f"{username_field}/0", pathsep="/")
    user["first_name"] = dictor(user_identity, f"{firstname_field}/0", pathsep="/")
    user["last_name"] = dictor(user_identity, f"{lastname_field}/0", pathsep="/")
    user["token"] = dictor(user_identity, f"{token_field}.0")

    if user["email"]:
        user["email"] = user["email"].lower()
    if user["username"]:
        user["username"] = user["username"].lower()

    # For backwards compatibility
    user["user_identity"] = user_identity

    if not user["email"] and not user["username"]:
        raise SAMLAuthError("No username or email provided.", extra={
            "exc_type": ValueError,
            "error_code": NO_USERNAME_OR_EMAIL_SPECIFIED,
            "reason": "Username or email must be configured on the SAML app before logging in.",
            "status_code": 422
        })

    if not user["token"]:
        raise SAMLAuthError("No token specified.", extra={
            "exc_type": ValueError,
            "error_code": NO_TOKEN_SPECIFIED,
            "reason": "Token must be configured on the SAML app before logging in.",
            "status_code": 422
        })

    return user
