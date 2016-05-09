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
from django.contrib.auth.models import (User, Group)
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.template import TemplateDoesNotExist
from django.http import HttpResponseRedirect

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


def get_current_domain(r):
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http',
        host=r.get_host(),
    )


def get_reverse(objs):
    '''In order to support different django version, I have to do this '''
    from django.core.urlresolvers import reverse
    if objs.__class__.__name__ not in ['list', 'tuple']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))


def _get_saml_client(domain):
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])
    import tempfile
    tmp = tempfile.NamedTemporaryFile()
    f = open(tmp.name, 'w')
    f.write(_urllib.urlopen(settings.SAML2_AUTH['METADATA_AUTO_CONF_URL']).read())
    f.close()
    saml_settings = {
        'metadata': {
            'local': [tmp.name],
        },
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

    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    tmp.close()
    return saml_client


@login_required
def welcome(r):
    try:
        return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(get_reverse('admin:index'))


def denied(r):
    return render(r, 'django_saml2_auth/denied.html')


def _create_new_user(username, email, firstname, lastname):
    user = User.objects.create_user(username, email)
    user.first_name = firstname
    user.last_name = lastname
    user.groups = [Group.objects.get(name=x) for x in settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('USER_GROUPS', [])]
    user.is_active = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('ACTIVE_STATUS', True)
    user.is_staff = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('STAFF_STATUS', True)
    user.is_superuser = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('SUPERUSER_STATUS', False)
    user.save()
    return user


@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r))
    resp = r.POST.get('SAMLResponse', None)
    next_url = r.session.get('login_next_url', get_reverse('admin:index'))

    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
    user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
    user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
    user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]

    target_user = None
    is_new_user = False

    try:
        target_user = User.objects.get(username=user_name)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)
    except User.DoesNotExist:
        target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
        is_new_user = True

    r.session.flush()

    if target_user.is_active:
        target_user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(r, target_user)
    else:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if is_new_user:
        try:
            return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


def signin(r):
    try:
        import urlparse as _urlparse
        from urllib import unquote
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    next_url = r.GET.get('next', get_reverse('admin:index'))

    try:
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = r.GET.get('next', get_reverse('admin:index'))

    r.session['login_next_url'] = next_url

    saml_client = _get_saml_client(get_current_domain(r))
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None

    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
            break

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return render(r, 'django_saml2_auth/signout.html')
