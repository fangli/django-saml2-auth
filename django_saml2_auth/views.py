#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib.parse as urlparse
from datetime import datetime, timedelta
from urllib.parse import unquote

import jwt
from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.http import is_safe_url
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version

from .utils import (create_new_user, decode_saml_response, default_next_url,
                    get_current_domain, get_reverse, get_saml_client, run_hook,
                    safe_get_index)


@login_required
def welcome(request: HttpRequest):
    try:
        return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(default_next_url())


def denied(request: HttpRequest):
    return render(request, 'django_saml2_auth/denied.html')


@csrf_exempt
def acs(request: HttpRequest):
    # default User or custom User. Now both will work.
    User = get_user_model()

    authn_response = decode_saml_response(request, acs, denied)
    user_identity = authn_response.get_identity()

    next_url = request.session.get('login_next_url') or default_next_url()
    # If relayState params is passed, use that else consider the previous 'next_url'
    next_url = request.POST.get('RelayState') or next_url

    user_email = safe_get_index(user_identity.get(settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('email', 'Email')), 0)
    user_name = safe_get_index(user_identity.get(settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('username', 'UserName')), 0)
    user_first_name = safe_get_index(user_identity.get(settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')), 0)
    user_last_name = safe_get_index(user_identity.get(settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('last_name', 'LastName')), 0)
    token = safe_get_index(user_identity.get(settings.SAML2_AUTH.get(
        'ATTRIBUTES_MAP', {}).get('token', 'Token')), 0)

    if not token:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    target_user = None
    is_new_user = False
    login_case_sensitive = True
    user_id = user_email if User.USERNAME_FIELD == 'email' else user_name

    # check whether the getting of the user object has to be case_sensitive or not
    # by default LOGIN_CASE_SENSITIVE = True
    login_case_sensitive = settings.SAML2_AUTH.get(
        'LOGIN_CASE_SENSITIVE', True)
    id_field = User.USERNAME_FIELD if login_case_sensitive else f"{User.USERNAME_FIELD}__iexact"

    try:
        target_user = User.objects.get(**{id_field: user_id})
    except User.DoesNotExist:
        new_user_should_be_created = settings.SAML2_AUTH.get(
            'CREATE_USER', True)
        if new_user_should_be_created:
            target_user = create_new_user(
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

    request.session.flush()

    # Retrieve user object from database again
    target_user = User.objects.get(**{id_field: user_id})

    if settings.SAML2_AUTH.get('USE_JWT') is True and target_user.is_active:
        # We use JWT auth send token to frontend
        jwt_secret = settings.SAML2_AUTH.get('JWT_SECRET')
        jwt_algorithm = settings.SAML2_AUTH.get('JWT_ALGORITHM')
        jwt_expiration = settings.SAML2_AUTH.get(
            'JWT_EXP', 60)  # default: 1 minute
        payload = {
            'email': target_user.email,
            'exp': (datetime.utcnow() +
                    timedelta(seconds=jwt_expiration)).timestamp()
        }
        jwt_token = jwt.encode(
            payload, jwt_secret, algorithm=jwt_algorithm).decode('ascii')
        query = f'?token={jwt_token}'

        frontend_url = settings.SAML2_AUTH.get(
            'FRONTEND_URL') or next_url

        return HttpResponseRedirect(frontend_url + query)

    if target_user.is_active:
        target_user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, target_user)

        if settings.SAML2_AUTH.get('TRIGGER', {}).get('AFTER_LOGIN', None):
            run_hook(settings.SAML2_AUTH['TRIGGER']['AFTER_LOGIN'],
                     request.session, user_identity)

    else:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if is_new_user:
        try:
            return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


def signin(request: HttpRequest):
    next_url = request.GET.get('next') or default_next_url()

    try:
        if 'next=' in unquote(next_url):
            next_url = urlparse.parse_qs(
                urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = request.GET.get('next') or default_next_url()

    # Only permit signin requests where the next_url is a safe URL
    allowed_hosts = set(settings.SAML2_AUTH.get(
        'ALLOWED_REDIRECT_HOSTS') or [])
    if parse_version(get_version()) >= parse_version('2.0'):
        url_ok = is_safe_url(next_url, allowed_hosts)
    else:
        url_ok = is_safe_url(next_url)

    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    request.session['login_next_url'] = next_url

    saml_client = get_saml_client(get_current_domain(request), acs)
    _, info = saml_client.prepare_for_authenticate(relay_state=next_url)

    redirect_url = None

    if 'Location' in info['headers']:
        redirect_url = info['headers']['Location']

    return HttpResponseRedirect(redirect_url)


def signout(request: HttpRequest):
    logout(request)
    return render(request, 'django_saml2_auth/signout.html')
