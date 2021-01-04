from datetime import datetime, timedelta
from functools import wraps
from typing import (Any, Callable, Dict, Iterable, Mapping, Optional, Tuple,
                    Type, Union)

import jwt
from dictor import dictor
from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models import Model
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils.module_loading import import_string
from pkg_resources import parse_version
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.response import AuthnResponse

from .errors import *
from .exceptions import SAMLAuthError


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
                "authn_requests_signed": True,
                "logout_requests_signed": True,
                "want_assertions_signed": dictor(
                    settings, "SAML2_AUTH.WANT_ASSERTIONS_SIGNED", default=True),
                "want_response_signed": dictor(
                    settings, "SAML2_AUTH.WANT_RESPONSE_SIGNED", default=True),
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
        acs: Callable[...]) -> Union[HttpResponseRedirect, Optional[AuthnResponse]]:
    """Given a request, the authentication response inside the SAML response body is parsed,
    decoded and returned. If there are any issues parsing the request, the identity or the issuer,
    an exception is raised.

    Args:
        request (HttpRequest): Django request object from identity provider (IdP)
        acs (Callable[...]): The acs endpoint

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

    Returns:
        Dict[str, Optional[Any]]: Cleaned user information plus user_identity
            for backwards compatibility
    """
    email_field = dictor(settings, "ATTRIBUTES_MAP.email", default="user.email")
    username_field = dictor(settings, "ATTRIBUTES_MAP.username", default="user.username")
    firstname_field = dictor(settings, "ATTRIBUTES_MAP.first_name", default="user.first_name")
    lastname_field = dictor(settings, "ATTRIBUTES_MAP.last_name", default="user.last_name")
    token_field = dictor(settings, "ATTRIBUTES_MAP.token", default="token")

    user = {}
    user["email"] = dictor(user_identity, f"{email_field}/0", pathsep="/")  # Path includes "."
    user["user_name"] = dictor(user_identity, f"{username_field}/0", pathsep="/")
    user["first_name"] = dictor(user_identity, f"{firstname_field}/0", pathsep="/")
    user["last_name"] = dictor(user_identity, f"{lastname_field}/0", pathsep=" /")
    user["token"] = dictor(user_identity, f"{token_field}.0")

    # For backwards compatibility
    user["user_identity"] = user_identity

    if not user["token"]:
        raise SAMLAuthError("No token specified.", extra={
            "exc_type": ValueError,
            "error_code": NO_TOKEN_SPECIFIED,
            "reason": "Token must be configured on the SAML app before logging in.",
            "status_code": 422
        })

    return user


def get_or_create_user(user: Dict[str, Any]) -> Tuple[bool, Type[Model]]:
    """Get or create a new user and optionally add it to one or more group(s)

    Args:
        user (Dict[str, Any]): User information

    Raises:
        SAMLAuthError: Cannot create user.

    Returns:
        Tuple[bool, Type[Model]]: A tuple containing user creation status and user object
    """
    user_model = get_user_model()
    created = False
    user_id = user["email"] if user_model.USERNAME_FIELD == "email" else user["user_name"]
    # Should email be case-sensitive or not. Default is False (case-insensitive).
    login_case_sensitive = dictor(settings, "SAML2_AUTH.LOGIN_CASE_SENSITIVE", default=False)
    id_field = (
        user_model.USERNAME_FIELD
        if login_case_sensitive
        else f"{user_model.USERNAME_FIELD}__iexact")

    try:
        target_user = user_model.objects.get(**{id_field: user_id})
    except user_model.DoesNotExist:
        should_create_new_user = dictor(settings, "SAML2_AUTH.CREATE_USER", default=True)
        if should_create_new_user:
            target_user = create_new_user(user["email"], user["first_name"], user["last_name"])

            create_user_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.CREATE_USER")
            if create_user_trigger:
                run_hook(create_user_trigger, user)

            created = True
        else:
            raise SAMLAuthError("Cannot create user.", extra={
                "exc_type": Exception,
                "error_code": SHOULD_NOT_CREATE_USER,
                "reason": "Due to current config, a new user should not be created.",
                "status_code": 500
            })

    # Optionally update this user's group assignments by updating group memberships from SAML groups
    # to Django equivalents
    group_attribute = dictor(settings, "SAML2_AUTH.ATTRIBUTES_MAP.groups")
    group_map = dictor(settings, "SAML2_AUTH.GROUPS_MAP")

    if group_attribute and group_attribute in user["user_identity"]:
        groups = []

        for group_name in user["user_identity"][group_attribute]:
            # Group names can optionally be mapped to different names in Django
            if group_map and group_name in group_map:
                group_name_django = group_map[group_name]
            else:
                group_name_django = group_name

            try:
                groups.append(Group.objects.get(name=group_name_django))
            except Group.DoesNotExist:
                pass

        if parse_version(get_version()) >= parse_version("2.0"):
            target_user.groups.set(groups)
        else:
            target_user.groups = groups

    return (created, target_user)


def create_jwt_token(target_user: Type[Model]) -> str:
    """Create a new JWT token

    Args:
        target_user (Type[Model]): A user object queried from DB

    Returns:
        str: JWT token
    """
    jwt_secret = dictor(settings, "SAML2_AUTH.JWT_SECRET")
    jwt_algorithm = dictor(settings, "SAML2_AUTH.JWT_ALGORITHM")
    jwt_expiration = dictor(settings, "SAML2_AUTH.JWT_EXP", default=60)  # default: 1 minute
    payload = {
        "email": target_user.email,
        "exp": (datetime.utcnow() +
                timedelta(seconds=jwt_expiration)).timestamp()
    }
    jwt_token = jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)
    return jwt_token


def exception_handler(function: Callable[...]) -> Callable[...]:
    """This decorator can be used by view function to handle exceptions

    Args:
        function (Callable[...]): View function to decorate

    Returns:
        Callable[...]: Decorated view function with exception handling
    """
    def handle_exception(exc: Exception, request: HttpRequest) -> HttpResponse:
        """Render page with exception details

        Args:
            exc (Exception): An exception
            request (HttpRequest): Incoming http request object

        Returns:
            HttpResponse: Rendered error page with details
        """
        return render(request, 'error.html', context=exc.extra, status=exc.extra["status_code"])

    @wraps(function)
    def wrapper(request: HttpRequest) -> HttpResponse:
        """Decorated function is wrapped and called here

        Args:
            request ([type]): [description]

        Returns:
            HttpResponse: Either a redirect or a response with error details
        """
        result = None
        try:
            result = function(request)
        except SAMLAuthError as exc:
            result = handle_exception(exc, request)
        return result
    return wrapper
