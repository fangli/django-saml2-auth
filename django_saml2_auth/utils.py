from typing import Any, Callable, Iterable, Mapping, Optional, Type, Tuple, Union

from django import get_version
from django.conf import settings
from django.db.models import Model
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.http import HttpRequest, HttpResponseRedirect
from django.urls import NoReverseMatch, reverse
from django.utils.module_loading import import_string
from pkg_resources import parse_version
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.response import AuthnResponse
from dictor import dictor


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
        ValueError: function_path isn't specified
        ValueError: There's nothing to import. Check your hook's import path!
        Exception: Re-raises any exception caused by import_string or the called function

    Returns:
        Optional[Any]: Any result returned from running the hook function. None is returned in case
            of any exceptions, errors in arguments and related issues.
    """
    if not function_path:
        raise ValueError("function_path isn't specified")

    path = function_path.split(".")
    if len(path) < 2:
        # Nothing to import
        raise ValueError("There's nothing to import. Check your hook's import path!")

    module_path = ".".join(path[:-1])
    result = None
    try:
        cls = import_string(module_path)
        result = getattr(cls, path[-1])(*args, **kwargs)
    except (ImportError, Exception) as exc:
        raise exc

    return result


def create_new_user(email: str, firstname: str, lastname: str) -> Type[Model]:
    """Create a new user with the given information

    Args:
        email (str): Email
        firstname (str): First name
        lastname (str): Last name

    Returns:
        Type[Model]: Returns a new user object, usually a subclass of the the User model
    """
    user_model = get_user_model()

    is_active = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.ACTIVE_STATUS", default=True)
    is_staff = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.STAFF_STATUS", default=False)
    is_superuser = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.SUPERUSER_STATUS", default=False)
    user_groups = dictor(settings, "SAML2_AUTH.NEW_USER_PROFILE.USER_GROUPS", default=[])

    user = user_model.objects.create_user(
        email, first_name=firstname, last_name=lastname,
        is_active=is_active, is_staff=is_staff, is_superuser=is_superuser)

    groups = [Group.objects.get(name=group) for group in user_groups]
    if groups:
        if parse_version(get_version()) <= parse_version("1.8"):
            user.groups = groups
        else:
            user.groups.set(groups)

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
        Exception: If the function fails to return anything, an exception is raised.

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
    raise Exception(
        f"We got a URL reverse issue: {str(objects)}. This is a known issue but please still "
        "submit a ticket at https://github.com/loadimpact/django-saml2-auth/issues/new")


def get_metadata() -> Mapping[str, Any]:
    """Returns metadata information, either by running the GET_METADATA_AUTO_CONF_URLS hook function
    if available, or by checking and returning a local file path or the METADATA_AUTO_CONF_URL.

    Returns:
        Mapping[str, Any]: Returns a metadata object as dictionary
    """
    get_metadata_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.GET_METADATA_AUTO_CONF_URLS")
    if get_metadata_trigger:
        metadata_urls = run_hook(get_metadata_trigger)
        return {"remote": metadata_urls}

    if dictor(settings, "SAML2_AUTH.METADATA_LOCAL_FILE_PATH"):
        return {"local": [dictor(settings, "SAML2_AUTH.METADATA_LOCAL_FILE_PATH")]}
    else:
        return {"remote": [{"url": dictor(settings, "SAML2_AUTH.METADATA_AUTO_CONF_URL")}]}


def get_saml_client(domain, acs) -> Optional[Saml2Client]:
    """Create a new Saml2Config object with the given config and return an initialized Saml2Client
    using the config object. The settings are read from django settings key: SAML2_AUTH.

    Args:
        domain ([type]): [description]
        acs ([type]): [description]

    Returns:
        Optional[Saml2Client]: [description]
    """
    acs_url = domain + get_reverse([acs, "acs", "django_saml2_auth:acs"])
    metadata = get_metadata()

    saml_settings = {
        "metadata": metadata,
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
                "want_assertions_signed": True,
                "want_response_signed": False,
            },
        },
    }

    if "ENTITY_ID" in settings.SAML2_AUTH:
        saml_settings["entityid"] = settings.SAML2_AUTH["ENTITY_ID"]

    if "NAME_ID_FORMAT" in settings.SAML2_AUTH:
        saml_settings["service"]["sp"]["name_id_format"] = settings.SAML2_AUTH["NAME_ID_FORMAT"]

    if "WANT_ASSERTIONS_SIGNED" in settings.SAML2_AUTH:
        saml_settings["service"]["sp"]["want_assertions_signed"] = settings.SAML2_AUTH[
            "WANT_ASSERTIONS_SIGNED"]

    if "WANT_RESPONSE_SIGNED" in settings.SAML2_AUTH:
        saml_settings["service"]["sp"]["want_response_signed"] = settings.SAML2_AUTH[
            "WANT_RESPONSE_SIGNED"]

    sp_config = Saml2Config()
    sp_config.load(saml_settings)
    sp_config.allow_unknown_attributes = True
    saml_client = Saml2Client(config=sp_config)
    return saml_client


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

    Returns:
        Union[HttpResponseRedirect, Optional[AuthnResponse]]: Returns an AuthnResponse object for
        extracting user identity from or a redirect to denied endpoint.
    """
    saml_client = get_saml_client(get_assertion_url(request), acs)
    response = request.POST.get("SAMLResponse") or None

    if not response:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))

    authn_response = saml_client.parse_authn_request_response(
        response, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))
    if authn_response.name_id is None:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))

    entity_id = authn_response.issuer()
    if entity_id is None:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))

    return authn_response
