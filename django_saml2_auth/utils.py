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


def run_hook(function_path: str,
             *args: Optional[Tuple[Any]],
             **kwargs: Optional[Mapping[str, Any]]) -> Any:
    """Runs a hook function with given args and kwargs. Given 'models.User.create_new_user',
    the 'create_new_user' function is imported from the 'models.User' module and
    ran with args and kwargs.

    Args:
        function_path (str): A path to a hook function,
            e.g. models.User.create_new_user (static method)

    Returns:
        Any: Any result returned from running the hook function
    """
    pkg = function_path.split('.')
    cls_path = '.'.join(pkg[:-1])
    func = pkg[-1]
    cls = import_string(cls_path)
    return getattr(cls, func)(*args, **kwargs)


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

    user = user_model.objects.create_user(email)
    user.first_name = firstname
    user.last_name = lastname
    groups = [Group.objects.get(name=x) for x in settings.SAML2_AUTH.get(
        'NEW_USER_PROFILE', {}).get('USER_GROUPS', [])]
    if parse_version(get_version()) >= parse_version('2.0'):
        user.groups.set(groups)
    else:
        user.groups = groups
    user.is_active = settings.SAML2_AUTH.get(
        'NEW_USER_PROFILE', {}).get('ACTIVE_STATUS', True)
    user.is_staff = settings.SAML2_AUTH.get(
        'NEW_USER_PROFILE', {}).get('STAFF_STATUS', True)
    user.is_superuser = settings.SAML2_AUTH.get(
        'NEW_USER_PROFILE', {}).get('SUPERUSER_STATUS', False)
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
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']

    protocol = 'https' if request.is_secure() else 'http'
    host = request.get_host()
    return f'{protocol}://{host}'


def get_default_next_url() -> Optional[str]:
    """Get default next url for redirection, which is either the DEFAULT_NEXT_URL from settings or
    admin index.

    Returns:
        Optional[str]: Returns default next url for redirection or index
    """
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse('admin:index')


def safe_get_index(iterable: Iterable, index: int) -> Optional[Any]:
    """Given a list and an index, returns the item at index or None

    Args:
        iterable (Iterable): An iterable, e.g. a list of items
        index (int): Index in a given iterable

    Returns:
        Optional[Any]: Returns the item at the given index or None
    """
    try:
        return iterable[index]
    except IndexError:
        return None


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
        f'We got a URL reverse issue: {str(objects)}. This is a known issue but please still '
        'submit a ticket at https://github.com/loadimpact/django-saml2-auth/issues/new')


def get_metadata() -> Mapping[str, Any]:
    """Returns metadata information, either by running the GET_METADATA_AUTO_CONF_URLS hook function
    if available, or by checking and returning a local file path or the METADATA_AUTO_CONF_URL.

    Returns:
        Mapping[str, Any]: Returns a metadata object as dictionary
    """
    if settings.SAML2_AUTH.get('TRIGGER', {}).get('GET_METADATA_AUTO_CONF_URLS', None):
        metadata_urls = run_hook(
            settings.SAML2_AUTH['TRIGGER']['GET_METADATA_AUTO_CONF_URLS'])
        return {
            'remote': metadata_urls
        }

    if 'METADATA_LOCAL_FILE_PATH' in settings.SAML2_AUTH:
        return {
            'local': [settings.SAML2_AUTH['METADATA_LOCAL_FILE_PATH']]
        }
    else:
        return {
            'remote': [
                {
                    "url": settings.SAML2_AUTH['METADATA_AUTO_CONF_URL'],
                },
            ]
        }


def get_saml_client(domain, acs) -> Optional[Saml2Client]:
    """Create a new Saml2Config object with the given config and return an initialized Saml2Client
    using the config object. The settings are read from django settings key: SAML2_AUTH.

    Args:
        domain ([type]): [description]
        acs ([type]): [description]

    Returns:
        Optional[Saml2Client]: [description]
    """
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])
    metadata = get_metadata()

    saml_settings = {
        'metadata': metadata,
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }

    if 'ENTITY_ID' in settings.SAML2_AUTH:
        saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

    if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

    if 'WANT_ASSERTIONS_SIGNED' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['want_assertions_signed'] = settings.SAML2_AUTH[
            'WANT_ASSERTIONS_SIGNED']

    if 'WANT_RESPONSE_SIGNED' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['want_response_signed'] = settings.SAML2_AUTH[
            'WANT_RESPONSE_SIGNED']

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
    decoded and returned. If there's any issues parsing the request, the identity or the issuer,
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
    response = request.POST.get('SAMLResponse') or None

    if not response:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        response, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))
    if authn_response.name_id is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    entity_id = authn_response.issuer()
    if entity_id is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    return authn_response
