#!/usr/bin/env python
# -*- coding:utf-8 -*-

from datetime import datetime, timedelta

from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.http import is_safe_url
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version
import jwt
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

try:
    import urlparse as _urlparse
    from urllib import unquote
except:
    import urllib.parse as _urlparse
    from urllib.parse import unquote

if parse_version(get_version()) >= parse_version('1.10'):
    from django.urls import NoReverseMatch, reverse
else:
    from django.core.urlresolvers import NoReverseMatch, reverse

if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


# default User or custom User. Now both will work.
User = get_user_model()


def _default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse('admin:index')


def get_current_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http',
        host=r.get_host(),
    )


def get_reverse(objs):
    if not isinstance(objs, (list, tuple)):
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except NoReverseMatch:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))


def _get_metadata():
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


def _get_saml_client(domain):
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])
    metadata = _get_metadata()

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

    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


def run_hook(func_path, *args, **kwargs):
    pkg = func_path.split('.')
    klass_path = '.'.join(pkg[:-1])
    func = pkg[-1]
    klass = import_string(klass_path)
    return getattr(klass, func)(*args, **kwargs)


@login_required
def welcome(r):
    try:
        return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(_default_next_url())


def denied(r):
    return render(r, 'django_saml2_auth/denied.html')


def _create_new_user(email, firstname, lastname):
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


@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r))
    resp = r.POST.get('SAMLResponse') or None
    next_url = r.session.get('login_next_url') or _default_next_url()
    # If relayState params is passed, use that else consider the previous 'next_url'
    next_url = r.POST.get('RelayState') or next_url

    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_email = user_identity[settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
    user_name = user_identity[settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
    user_first_name = user_identity[settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
    user_last_name = user_identity[settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]

    target_user = None
    is_new_user = False
    login_case_sensitive = True

    try:
        # check whether the getting of the user object has to be case_sensitive or not
        # by default LOGIN_CASE_SENSITIVE = True
        login_case_sensitive = settings.SAML2_AUTH.get(
            'LOGIN_CASE_SENSITIVE', True)

        if login_case_sensitive:
            target_user = User.objects.get(
                **{User.USERNAME_FIELD: user_name})
        else:
            target_user = User.objects.get(
                {User.USERNAME_FIELD__iexact: user_name})
    except User.DoesNotExist:
        new_user_should_be_created = settings.SAML2_AUTH.get(
            'CREATE_USER', True)
        if new_user_should_be_created:
            target_user = _create_new_user(
                user_email, user_first_name, user_last_name)

            if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
                run_hook(settings.SAML2_AUTH['TRIGGER']
                         ['CREATE_USER'], user_identity)

            is_new_user = True
        else:
            return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
        run_hook(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'], user_identity)

    # Optionally update this user's group assignments
    group_attribute = settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('groups', None)
    group_map = settings.SAML2_AUTH.get('GROUPS_MAP', None)

    if group_attribute and group_attribute in user_identity:
        groups = []

        for group_name in user_identity[group_attribute]:
            # Group names can optionally be mapped to different names in Django
            if group_map and group_name in group_map:
                group_name_django = group_map[group_name]
            else:
                group_name_django = group_name

            try:
                groups.append(Group.objects.get(name=group_name_django))
            except Group.DoesNotExist:
                pass

        if parse_version(get_version()) >= parse_version('2.0'):
            target_user.groups.set(groups)
        else:
            target_user.groups = groups

    r.session.flush()

    if login_case_sensitive:
        target_user = User.objects.get(
            **{User.USERNAME_FIELD: user_name})
    else:
        target_user = User.objects.get(
            {User.USERNAME_FIELD__iexact: user_name})

    if target_user.is_active:
        target_user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(r, target_user)

        if settings.SAML2_AUTH.get('TRIGGER', {}).get('AFTER_LOGIN', None):
            run_hook(settings.SAML2_AUTH['TRIGGER']['AFTER_LOGIN'],
                     r.session, user_identity)

    else:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if settings.SAML2_AUTH.get('USE_JWT') is True:
        # We use JWT auth send token to frontend
        jwt_secret = settings.SAML2_AUTH.get('JWT_SECRET')
        jwt_expiration = settings.SAML2_AUTH.get(
            'JWT_EXP', 60)  # default: 1 minute
        payload = {
            'email': target_user.email,
            'exp': (datetime.utcnow() +
                    timedelta(seconds=jwt_expiration)).timestamp()
        }
        jwt_token = jwt.encode(
            payload, jwt_secret, algorithm='HS256')
        query = '?token={}'.format(jwt_token)

        frontend_url = settings.SAML2_AUTH.get(
            'FRONTEND_URL') or next_url

        return HttpResponseRedirect(frontend_url + query)

    if is_new_user:
        try:
            return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


def signin(r):
    next_url = r.GET.get('next') or _default_next_url()

    try:
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(
                _urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = r.GET.get('next') or _default_next_url()

    # Only permit signin requests where the next_url is a safe URL
    allowed_hosts = set(settings.SAML2_AUTH.get(
        'ALLOWED_REDIRECT_HOSTS') or [])
    if parse_version(get_version()) >= parse_version('2.0'):
        url_ok = is_safe_url(next_url, allowed_hosts)
    else:
        url_ok = is_safe_url(next_url)

    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    r.session['login_next_url'] = next_url

    saml_client = _get_saml_client(get_current_domain(r))
    _, info = saml_client.prepare_for_authenticate(relay_state=next_url)

    redirect_url = None

    if 'Location' in info['headers']:
        redirect_url = info['headers']['Location']

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return render(r, 'django_saml2_auth/signout.html')
