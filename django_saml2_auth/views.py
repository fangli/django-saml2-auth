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

# Default User
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
    else:
        return get_reverse('start_page')

def get_current_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http', 
        host=r.get_host(),
    )

def get_reverse(objects):
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    if objects.__class__.__name__ not in ['list', 'tuple']:
        objects = [objects]

    for obj in objects:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception('URL reverse issue: %s.  Known issue from fangli/django-saml2-auth' % str(objects))

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
    # Create a new user object with the parameters passed
    user = User.objects.create_user(username, email)
    user.first_name = firstname
    user.last_name = lastname

    # Obtain the Customer group instance
    group = Group.objects.get(name='Customers')

    # Set user properties according to SAML2_AUTH configuration
    group.user_set.add(user)
    user.is_active = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('ACTIVE_STATUS', True) # Default to true if not found
    user.is_staff = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('STAFF_STATUS', False) # Default to false if not found
    user.is_superuser = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('SUPERUSER_STATUS', False) # Default to false if not found

    # Save changes to the new user instance
    user.save()
    return user

@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r))
    resp = r.POST.get('SAMLResponse', None)
    next_url = r.session.get('login_next_url', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', get_reverse('start_page')))

    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))
    
    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    # For Azure Active Directory Mapping
    user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')][0]
    user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')][0]
    user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname')][0]
    user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname')][0]

    target_user = None
    is_new_user = False

    # Try to query the user by the username
    try:
        target_user = User.objects.get(username=user_name)
    # If the User DNE, create a new user with their provided credentials
    except User.DoesNotExist:
        # Create a new user
        target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'](user_identity)

    r.session.flush()

    # If the user is active, we want to login
    if target_user.is_active:
        # Authenticate the user
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'](user_identity)
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
