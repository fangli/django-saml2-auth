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
from logging import getLogger
from book.models import Organization
from integration.serializers import ReferralCreatorSerializer
from refer.utils import PasswordlessAuthBackend
from django.shortcuts import redirect
from django.urls import reverse

logger = getLogger('django-saml2-auth')

# Default User
User = get_user_model()

# Obtain urllib imports based on installed services
try:
    import urllib2 as _urllib
except:
    import urllib.request as _urllib
    import urllib.error
    import urllib.parse

# Obtain import_string based on installed versions
if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string

# Helper function to obtain the default url the user should go to after login
def _default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    else:
        return 'lead_creator_dashboard'

# Helper function to obtain the domain based on the assertion url for the client
def get_current_domain(r):
    # If there is an assertion url in the saml2 schema, return its value
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    # Return the formatted scheme and host (https or http)
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http', 
        host=r.get_host(),
    )

# Helper function to call the avaiable reverse function on a list of objects
def get_reverse(objects):
    # Obtain the import based on installed versions
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    # If the object is not in the correct data structure, reformat here    
    if objects.__class__.__name__ not in ['list', 'tuple']:
        objects = [objects]

    # For each object in the list of objects, call reverse()
    for obj in objects:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception('URL reverse issue: %s.  Known issue from fangli/django-saml2-auth' % str(objects))

# Helper function to obtain the client metadata
def _get_metadata():
    # If the metadata local file path is confiugred in the saml2 schema, return its formatted value here
    if 'METADATA_LOCAL_FILE_PATH' in settings.SAML2_AUTH:
        return {
            'local': [settings.SAML2_AUTH['METADATA_LOCAL_FILE_PATH']]
        }
    # Otherwise, return the formatted value for the metadata url
    else:
        return {
            'remote': [
                {
                    "url": settings.SAML2_AUTH['METADATA_AUTO_CONF_URL'],
                },
            ]
        }

# Helper function to obtain the saml client given the host domain
def _get_saml_client(domain):
    # Create acs_url based on domain and acs url
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])
    # Obtain the request/client metadata
    metadata = _get_metadata()

    # Configure the saml settings for this client
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

    # If the entity id is configured in the saml schema, add its value to the saml settings
    if 'ENTITY_ID' in settings.SAML2_AUTH:
        saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

    # If the name id format is configured in the saml schema, add its value to the saml settings
    if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

    # Instantiate Saml2Config and Saml2Client with completed configuration
    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)

    # Return the client
    return saml_client

# Helper function to return the custom welcome template if it exists
@login_required
def welcome(r):
    # Attempt to render the custom template
    try:
        return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    # Otherwise, return the default next url
    except TemplateDoesNotExist:
        return HttpResponseRedirect(_default_next_url())

# Helper function to render the custom denied template
def denied(r):
    return render(r, 'django_saml2_auth/denied.html')

# Helper function to create a new user, assign to the 'Customers' group, and create a new lead creator for the specified organization
def _create_new_user_and_lead_creator(username, email, firstname, lastname, org_name):
    logger.debug('_create_new_user')
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
    user.set_unusable_password()

    # Save changes to the new user instance
    user.save()
    logger.debug('new user success')

    # Add user to lead creator instance
    try:
        org = Organization.objects.get(name=org_name)
    except Organization.DoesNotExist:
        raise Exception('Organization does not exist')

    # Instantiate a new lead creator
    leadCreator = ReferralCreatorSerializer(data={'organization': org.id, 'django_user': user.id})
    if leadCreator.is_valid():
        leadCreator.save()
        logger.debug('New lead creator success')
    else:
        logger.debug('New lead creator failure')
    
    return user

# View function, hit on url saml2_auth/acs/ after user login
@csrf_exempt
def acs(r):
    logger.debug('acs')

    # Obtain the saml client
    saml_client = _get_saml_client(get_current_domain(r))
    # Obtain the response after calling the POST method
    resp = r.POST.get('SAMLResponse', None)
    # Set the next url to the request session 'login_next_url'
    # If it doesn't exist, try getting the value from the saml schema, or default to 'lead_creator_dashboard'
    next_url = r.session.get('login_next_url', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', 'lead_creator_dashboard'))

    # If no response was returned from the POST method, redirect to the denied page
    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    # Obtain the authn response from the client
    authn_response = saml_client.parse_authn_request_response(resp, entity.BINDING_HTTP_POST)

    # If no authn response was returned, redirect to the denied page
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))
    
    # Obtain the user identity from the authn response
    user_identity = authn_response.get_identity()

    # If no user identity is returned, redirect to the denied page
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    # For Azure Active Directory Mapping -> pull value from saml schema or default to the explicit identity claim (varies on provider)
    user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')][0]
    user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')][0]
    user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname')][0]
    user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname')][0]
    org_name = settings.SAML2_AUTH['ORGANIZATION_NAME']

    target_user = None
    is_new_user = False

    # Try to query the user by the username
    try:
        target_user = User.objects.get(username=user_name)
    # If the User DNE, create a new user with their provided credentials
    except User.DoesNotExist:
        # Create a new user
        target_user = _create_new_user_and_lead_creator(user_name, user_email, user_first_name, user_last_name, org_name)
        is_new_user = True
			  
    # If the user is active, we want to login
    if target_user.is_active:
        logger.debug('trying to authenticate')

        # Authenticate the user
        target_user.backend = 'django.contrib.auth.backends.ModelBackend'
        # Login
        login(r, target_user)

        # Flush the session
        r.session.flush()

        # If the user is a new user, try to render the custom welcome template
        if is_new_user:
            try:
                return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
            except TemplateDoesNotExist:
                return redirect(reverse((next_url))
        # Otherwise, redirect to the default next url
        else:
            return redirect(reverse(next_url))
    # Otherwise, redirect to the denied page
    else:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

# View function, hit on url tch/login/ to take user to organization login
def signin(r):
    # Try to import the required dependencies based on installed versions
    try:
        import urlparse as _urlparse
        from urllib import unquote
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    
    # Set next_url to result of default function
    next_url = r.GET.get('next', _default_next_url())

    # Check if url contains 'next=' for url redirect
    try:
        # If the url contains 'next=', parse the url and use as the next_url
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
    # Otherwise, use the result of the default function
    except:
        next_url = r.GET.get('next', _default_next_url())
    
    # Only permit signin requests where the next_url is a safe URL
    if parse_version(get_version()) >= parse_version('2.0'):
        url_ok = is_safe_url(next_url, None)
    else:
        url_ok = is_safe_url(next_url)

    # If the url is not safe, redirect to the denied page
    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    # Set the session login_next_url to the validated next_url
    r.session['login_next_url'] = next_url

    # Obtain the saml client
    saml_client = _get_saml_client(get_current_domain(r))
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None

    # For each key and value in the information header returned from the client,
    for key, value in info['headers']:
        # Check if there is a key named 'Location'
        if key == 'Location':
            # If so, set this as the redirect_url
            redirect_url = value
            break
    
    return HttpResponseRedirect(redirect_url)

# Helper function to logout and render the custom signout page
def signout(r):
    logout(r)
    return render(r, 'django_saml2_auth/signout.html')
