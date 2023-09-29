#!/usr/bin/env python
# -*- coding:utf-8 -*-


from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django import get_version
from pkg_resources import parse_version
from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, get_user_model
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.template import TemplateDoesNotExist
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url
from tempfile import NamedTemporaryFile
import contextlib



from rest_auth.utils import jwt_encode

from .models import SamlMetaData


# default User or custom User. Now both will work.
User = get_user_model()

try:
    import urllib2 as _urllib
except:
    import urllib.request as _urllib
    import urllib.error
    import urllib.parse

if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


def _default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse('admin:index')


def get_current_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https',
        host=r.get_host(),
    )


def get_reverse(objs, reverse_args = None):
    '''In order to support different django version, I have to do this '''
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    if objs.__class__.__name__ not in ['list', 'tuple']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj, args=reverse_args)
        except:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))

@contextlib.contextmanager
def _initialize_temp_file(metadata_contents):
    tmp = NamedTemporaryFile(mode="w+")
    tmp.write(metadata_contents)
    tmp.seek(0)

    yield tmp

    tmp.close()

def _wrap_url(path):
    return {
        "local": [path]
    }

def _get_saml_client(domain, metadata_id):
    acs_url = domain + get_reverse(["django_saml2_auth:acs"], reverse_args=[metadata_id])

    metadata_model = SamlMetaData.objects.get(pk=metadata_id)
    content = metadata_model.metadata_contents

    with _initialize_temp_file(content) as tmp:            
        wrapped_metadata_path = _wrap_url(tmp.name)

        saml_settings = {
            'metadata': wrapped_metadata_path,
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

        # as acs urls now include metadata IDs, dynamically set the entity ID
        saml_settings["entityid"] = acs_url

        if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
            saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

        spConfig = Saml2Config()
        spConfig.load(saml_settings)
        spConfig.allow_unknown_attributes = True

        saml_client = Saml2Client(config=spConfig)
        return saml_client


@login_required
def welcome(r):
    try:
        return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(_default_next_url())


def denied(r):
    return render(r, 'django_saml2_auth/denied.html')


def _create_new_user(username, email, firstname, lastname):
    user = User.objects.create_user(username, email)
    user.first_name = firstname
    user.last_name = lastname
    groups = [Group.objects.get(name=x) for x in settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('USER_GROUPS', [])]
    if parse_version(get_version()) >= parse_version('2.0'):
        user.groups.set(groups)
    else:
        user.groups = groups
    user.is_active = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('ACTIVE_STATUS', True)
    user.is_staff = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('STAFF_STATUS', True)
    user.is_superuser = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('SUPERUSER_STATUS', False)
    user.save()
    return user

@csrf_exempt
def acs(r, metadata_id):
    metadata = SamlMetaData.objects.filter(pk=metadata_id).first()
    if not metadata:
        print("Denied because missing metadata")
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    expected_email_domain = metadata.email_domain

    saml_client = _get_saml_client(get_current_domain(r), metadata_id)
    resp = r.POST.get('SAMLResponse', None)
    
    next_url = r.session.get('login_next_url', _default_next_url())
    # use relay state to redirect due to issue described here
    # https://github.com/fangli/django-saml2-auth/issues/112#issuecomment-529542145
    next_url = r.POST.get('RelayState', next_url)

    if not resp:
        print("Denied because no SAMLResponse")
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    # must have all IDPs configure this value to return principal's email
    user_name_id = None
    try:
        user_subject = authn_response.get_subject()
        user_name_id = user_subject.text
    except:
        print("Denied because no user_name_id")
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    # NOTE: to protect against exploit caused by malicious config of other idps
    user_email_domain = user_name_id.split("@")[1]
    if not expected_email_domain == user_email_domain:
        print("Denied because unexpected email domain")
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"])
        )

    user_identity = authn_response.get_identity()
    if user_identity is None:
        print("Denied because no user_identity")
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))
    
    target_user = None
    is_new_user = False

    try:
        target_user = User.objects.get(username=user_name_id)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)
    except User.DoesNotExist:
        new_user_should_be_created = settings.SAML2_AUTH.get('CREATE_USER', True)
        if new_user_should_be_created: 
            user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
            user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
            user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
            user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]

            target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name)
            if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
                import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
            is_new_user = True
        else:
            print("Denied because no user exists")
            return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    r.session.flush()

    if target_user.is_active:
        target_user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(r, target_user)
    else:
        print("Denied because user is not active")
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if settings.SAML2_AUTH.get('USE_JWT') is True:
        # We use JWT auth send token to frontend
        jwt_token = jwt_encode(target_user)
        query = '?uid={}&token={}'.format(target_user.id, jwt_token)

        frontend_url = settings.SAML2_AUTH.get(
            'FRONTEND_URL', next_url)

        return HttpResponseRedirect(frontend_url+query)

    if is_new_user:
        try:
            return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


def signin(r, metadata_id):
    try:
        import urlparse as _urlparse
        from urllib import unquote
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    next_url = r.GET.get('next', _default_next_url())

    try:
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = r.GET.get('next', _default_next_url())

    # Only permit signin requests where the next_url is a safe URL
    if parse_version(get_version()) >= parse_version('2.0'):
        url_ok = is_safe_url(next_url, None)
    else:
        url_ok = is_safe_url(next_url)

    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    r.session['login_next_url'] = next_url
    
    saml_client = _get_saml_client(get_current_domain(r), metadata_id)
    _, info = saml_client.prepare_for_authenticate(relay_state=next_url)

    redirect_url = None

    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
            break

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return render(r, 'django_saml2_auth/signout.html')
