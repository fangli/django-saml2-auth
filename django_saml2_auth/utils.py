from functools import wraps
from typing import (Any, Callable, Iterable, Mapping, Optional, Tuple, Type,
                    Union)

from dictor import dictor
from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models import Model
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils.module_loading import import_string
from pkg_resources import parse_version
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.response import AuthnResponse

from .exceptions import SAMLAuthError
from .errors import *


def run_hook(function_path: str,
             *args: Optional[Tuple[Any]],
             **kwargs: Optional[Mapping[str, Any]]) -> Optional[Any]:
    """Runs a hook function with given args and kwargs. For example, given
    "models.User.create_new_user", the "create_new_user" function is imported from
    the "models.User" module and run with args and kwargs.

    Args:
        function_path (str): A path to a hook function,
            e.g. models.User.create_new_user (static method)

    Raises:
        SAMLAuthError: function_path isn't specified
        SAMLAuthError: There's nothing to import. Check your hook's import path!
        SAMLAuthError: Import error
        SAMLAuthError: Re-raise any exception caused by the called function

    Returns:
        Optional[Any]: Any result returned from running the hook function. None is returned in case
            of any exceptions, errors in arguments and related issues.
    """
    if not function_path:
        raise SAMLAuthError("function_path isn't specified", extra={
            "exc_type": ValueError,
            "error_code": EMPTY_FUNCTION_PATH,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    path = function_path.split(".")
    if len(path) < 2:
        # Nothing to import
        raise SAMLAuthError("There's nothing to import. Check your hook's import path!", extra={
            "exc_type": ValueError,
            "error_code": PATH_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    module_path = ".".join(path[:-1])
    result = None
    try:
        cls = import_string(module_path)
        result = getattr(cls, path[-1])(*args, **kwargs)
    except ImportError as exc:
        raise SAMLAuthError(str(exc), extra={
            "exc_type": ImportError,
            "error_code": IMPORT_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })
    except Exception as exc:
        raise SAMLAuthError(str(exc), extra={
            "exc_type": type(exc),
            "error_code": GENERAL_EXCEPTION,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    return result


def create_new_user(email: str, firstname: str, lastname: str) -> Type[Model]:
    """Create a new user with the given information

    Args:
        email (str): Email
        firstname (str): First name
        lastname (str): Last name

    Raises:
        SAMLAuthError: There was an error creating the new user.
        SAMLAuthError: There was an error joining the user to the group.

    Returns:
        Type[Model]: Returns a new user object, usually a subclass of the the User model
    """
    user_model = get_user_model()

    is_active = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.ACTIVE_STATUS", default=True)
    is_staff = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.STAFF_STATUS", default=False)
    is_superuser = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.SUPERUSER_STATUS", default=False)
    user_groups = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.USER_GROUPS", default=[])

    try:
        user = user_model.objects.create_user(
            email, first_name=firstname, last_name=lastname,
            is_active=is_active, is_staff=is_staff, is_superuser=is_superuser)
    except Exception as exc:
        raise SAMLAuthError("There was an error creating the new user.", extra={
            "exc_type": type(exc),
            "error_code": CREATE_USER_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    try:
        groups = [Group.objects.get(name=group) for group in user_groups]
        if groups:
            if parse_version(get_version()) <= parse_version("1.8"):
                user.groups = groups
            else:
                user.groups.set(groups)
    except Exception as exc:
        raise SAMLAuthError("There was an error joining the user to the group.", extra={
            "exc_type": type(exc),
            "error_code": GROUP_JOIN_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    user.save()
    user.refresh_from_db()

    return user


def get_assertion_url(request: HttpRequest) -> str:
    """Extract protocol and domain name from request, if ASSERTION_URL is not specified in settings,
    otherwise the ASSERTION_URL is returned.

    Args:
        request (HttpRequest): Django request object

    Returns:
        str: Either protocol://host or ASSERTION_URL
    """
    assertion_url = dictor(settings, "SAML2_AUTH.ASSERTION_URL")
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
    default_next_url = dictor(settings, "SAML2_AUTH.DEFAULT_NEXT_URL")
    if default_next_url:
        return default_next_url

    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse("admin:index")


def get_reverse(objects: Union[Any, Iterable[Any]]) -> Optional[str]:
    """Given one or a list of views/urls(s), returns the corresponding URL to that view.

    Args:
        objects (Union[Any, Iterable[Any]]): One or many views/urls representing a resource

    Raises:
        SAMLAuthError: We got a URL reverse issue: [...]

    Returns:
        Optional[str]: The URL to the resource or None.
    """
    if not isinstance(objects, (list, tuple)):
        objects = [objects]

    for obj in objects:
        try:
            return reverse(obj)
        except NoReverseMatch:
            pass
    raise SAMLAuthError(f"We got a URL reverse issue: {str(objects)}", extra={
        "exc_type": type(NoReverseMatch),
        "error_code": NO_REVERSE_MATCH,
        "reason": "There was an error processing your request.",
        "status_code": 500
    })


def get_metadata() -> Mapping[str, Any]:
    """Returns metadata information, either by running the GET_METADATA_AUTO_CONF_URLS hook function
    if available, or by checking and returning a local file path or the METADATA_AUTO_CONF_URL.

    Returns:
        Mapping[str, Any]: Returns a SAML metadata object as dictionary
    """
    get_metadata_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.GET_METADATA_AUTO_CONF_URLS")
    if get_metadata_trigger:
        metadata_urls = run_hook(get_metadata_trigger)
        return {"remote": metadata_urls}

    metadata_local_file_path = dictor(settings, "SAML2_AUTH.METADATA_LOCAL_FILE_PATH")
    if metadata_local_file_path:
        return {"local": [metadata_local_file_path]}
    else:
        single_metadata_url = dictor(settings, "SAML2_AUTH.METADATA_AUTO_CONF_URL")
        return {"remote": [{"url": single_metadata_url}]}


def get_saml_client(domain: str, acs: Callable[...]) -> Optional[Saml2Client]:
    """Create a new Saml2Config object with the given config and return an initialized Saml2Client
    using the config object. The settings are read from django settings key: SAML2_AUTH.

    Args:
        domain (str): Domain name to get SAML config for
        acs (Callable[...]): The acs endpoint

    Raises:
        SAMLAuthError: Re-raise any exception raised by Saml2Config or Saml2Client

    Returns:
        Optional[Saml2Client]: A Saml2Client or None
    """
    acs_url = domain + get_reverse([acs, "acs", "django_saml2_auth:acs"])
    metadata = get_metadata()

    saml_settings = {
        "metadata": metadata,
        "allow_unknown_attributes": True,
        "debug": dictor(settings, "SAML2_AUTH.DEBUG", default=False),
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                "allow_unsolicited": True,
                "authn_requests_signed": False,
                "logout_requests_signed": True,
                "want_assertions_signed": dictor(
                    settings, "SAML2_AUTH.WANT_ASSERTIONS_SIGNED", default=True),
                "want_response_signed": dictor(
                    settings, "SAML2_AUTH.WANT_RESPONSE_SIGNED", default=False),
            },
        },
    }

    entity_id = dictor(settings, "SAML2_AUTH.ENTITY_ID")
    if entity_id:
        saml_settings["entityid"] = entity_id

    name_id_format = dictor(settings, "SAML2_AUTH.NAME_ID_FORMAT")
    if name_id_format:
        saml_settings["service"]["sp"]["name_id_format"] = name_id_format

    try:
        sp_config = Saml2Config()
        sp_config.load(saml_settings)
        saml_client = Saml2Client(config=sp_config)
        return saml_client
    except Exception as exc:
        raise SAMLAuthError(str(exc), extra={
            "exc_type": type(exc),
            "error_code": ERROR_CREATING_SAML_CONFIG_OR_CLIENT,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })


def decode_saml_response(
        request: HttpRequest,
        acs: Callable[...],
        denied: Callable[...]) -> Union[HttpResponseRedirect, Optional[AuthnResponse]]:
    """Given a request, the authentication response inside the SAML response body is parsed,
    decoded and returned. If there"s any issues parsing the request, the identity or the issuer,
    the user is redirected to denied page.

    Args:
        request (HttpRequest): Django request object from identity provider (IdP)
        acs (Callable[...]): The acs endpoint
        denied (Callable[...]): The denied endpoint

    Raises:
        SAMLAuthError: There was no response from SAML client.
        SAMLAuthError: There was no response from SAML identity provider.
        SAMLAuthError: No name_id in SAML response.
        SAMLAuthError: No issuer/entity_id in SAML response.
        SAMLAuthError: No user identity in SAML response.

    Returns:
        Union[HttpResponseRedirect, Optional[AuthnResponse]]: Returns an AuthnResponse object for
        extracting user identity from or a redirect to denied endpoint.
    """
    saml_client = get_saml_client(get_assertion_url(request), acs)
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


def exception_handler(function):
    def handle_exception(exc, request):
        return render(request, 'error.html', context=exc.extra, status=exc.extra["status_code"])

    @wraps(function)
    def wrapper(request):
        result = None
        try:
            result = function(request)
        except SAMLAuthError as exc:
            result = handle_exception(exc, request)
        return result
    return wrapper
