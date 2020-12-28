from typing import Optional, Callable

from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.http import HttpRequest, HttpResponseRedirect
from pkg_resources import parse_version
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.response import AuthnResponse

if parse_version(get_version()) >= parse_version('1.10'):
    from django.urls import NoReverseMatch, reverse
else:
    from django.core.urlresolvers import NoReverseMatch, reverse

if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


def run_hook(func_path, *args, **kwargs):
    pkg = func_path.split('.')
    cls_path = '.'.join(pkg[:-1])
    func = pkg[-1]
    cls = import_string(cls_path)
    return getattr(cls, func)(*args, **kwargs)


def create_new_user(email, firstname, lastname):
    # default User or custom User. Now both will work.
    User = get_user_model()

    user = User.objects.create_user(email)
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
    return user


def get_current_domain(request: HttpRequest):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']

    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host()
    return f'{scheme}://{host}'


def default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse('admin:index')


def safe_get_index(lst, index):
    try:
        return lst[index]
    except IndexError:
        return None


def get_reverse(objs):
    if not isinstance(objs, (list, tuple)):
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except NoReverseMatch:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))


def get_metadata():
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
        saml_settings['service']['sp']['want_assertions_signed'] = settings.SAML2_AUTH['WANT_ASSERTIONS_SIGNED']

    if 'WANT_RESPONSE_SIGNED' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['want_response_signed'] = settings.SAML2_AUTH['WANT_RESPONSE_SIGNED']

    sp_config = Saml2Config()
    sp_config.load(saml_settings)
    sp_config.allow_unknown_attributes = True
    saml_client = Saml2Client(config=sp_config)
    return saml_client


def decode_saml_response(request: HttpRequest,
                         acs: Callable[...],
                         denied: Callable[...]) -> Optional[AuthnResponse]:
    saml_client = get_saml_client(get_current_domain(request), acs)
    resp = request.POST.get('SAMLResponse') or None

    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
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
