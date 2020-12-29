#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib.parse as urlparse
from datetime import datetime, timedelta
from urllib.parse import unquote

import jwt
from dictor import dictor
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

from .exceptions import SAMLAuthError
from .errors import *
from .utils import (create_new_user, decode_saml_response, get_assertion_url,
                    get_default_next_url, get_reverse, get_saml_client,
                    run_hook, exception_handler)


@login_required
def welcome(request: HttpRequest):
    try:
        return render(request, "django_saml2_auth/welcome.html", {"user": request.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(get_default_next_url())


def denied(request: HttpRequest):
    return render(request, "django_saml2_auth/denied.html")


@csrf_exempt
@exception_handler
def acs(request: HttpRequest):
    """Assertion Consumer Service is SAML terminology for the location at a ServiceProvider that
    accepts <samlp:Response> messages (or SAML artifacts) for the purpose of establishing a session
    based on an assertion. Assertion is a signed authentication request from identity provider (IdP)
    to acs endpoint.

    Args:
        request (HttpRequest): Incoming request from identity provider (IdP) for authentication

    Exceptions:
        SAMLAuthError: No token specified.
        SAMLAuthError: Cannot create user.
        SAMLAuthError: The target user is inactive.

    Returns:
        HttpResponseRedirect: Redirect to various endpoints: denied, welcome or next_url (e.g.
            the front-end app)

    Notes:
        https://wiki.shibboleth.net/confluence/display/CONCEPT/AssertionConsumerService
    """
    # default User or custom User. Now both will work.
    user_model = get_user_model()

    authn_response = decode_saml_response(request, acs, denied)
    user_identity = authn_response.get_identity()

    next_url = request.session.get("login_next_url") or get_default_next_url()
    # If relayState params is passed, use that else consider the previous "next_url"
    next_url = request.POST.get("RelayState") or next_url

    email_field = dictor(settings, "ATTRIBUTES_MAP.email", default="user.email")
    username_field = dictor(settings, "ATTRIBUTES_MAP.username", default="user.username")
    firstname_field = dictor(settings, "ATTRIBUTES_MAP.first_name", default="user.first_name")
    lastname_field = dictor(settings, "ATTRIBUTES_MAP.last_name", default="user.last_name")
    token_field = dictor(settings, "ATTRIBUTES_MAP.token", default="token")

    user_email = dictor(user_identity, f"{email_field}/0", pathsep="/")  # Path includes "."
    user_name = dictor(user_identity, f"{username_field}/0", pathsep="/")
    user_first_name = dictor(user_identity, f"{firstname_field}/0", pathsep="/")
    user_last_name = dictor(user_identity, f"{lastname_field}/0", pathsep="/")
    token = dictor(user_identity, f"{token_field}.0")

    if not token:
        raise SAMLAuthError("No token specified.", extra={
            "exc_type": ValueError,
            "error_code": NO_TOKEN_SPECIFIED,
            "reason": "Token must be configured on the SAML app before logging in.",
            "status_code": 422
        })

    target_user = None
    is_new_user = False
    login_case_sensitive = True
    user_id = user_email if user_model.USERNAME_FIELD == "email" else user_name
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
            target_user = create_new_user(user_email, user_first_name, user_last_name)

            create_user_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.CREATE_USER")
            if create_user_trigger:
                run_hook(create_user_trigger, user_identity)

            is_new_user = True
        else:
            raise SAMLAuthError("Cannot create user.", extra={
                "exc_type": Exception,
                "error_code": SHOULD_NOT_CREATE_USER,
                "reason": "Due to current config, a new user should not be created.",
                "status_code": 500
            })

    before_login_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.BEFORE_LOGIN")
    if before_login_trigger:
        run_hook(before_login_trigger, user_identity)

    # Optionally update this user's group assignments by updating group memberships from SAML groups
    # to Django equivalents
    group_attribute = dictor(settings, "SAML2_AUTH.ATTRIBUTES_MAP.groups")
    group_map = dictor(settings, "SAML2_AUTH.GROUPS_MAP")

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

        if parse_version(get_version()) >= parse_version("2.0"):
            target_user.groups.set(groups)
        else:
            target_user.groups = groups

    request.session.flush()

    # Retrieve user object from database again
    target_user = user_model.objects.get(**{id_field: user_id})

    use_jwt = dictor(settings, "SAML2_AUTH.USE_JWT", default=False)
    if use_jwt and target_user.is_active:
        # We use JWT auth to send token to frontend
        jwt_secret = dictor(settings, "SAML2_AUTH.JWT_SECRET")
        jwt_algorithm = dictor(settings, "SAML2_AUTH.JWT_ALGORITHM")
        jwt_expiration = dictor(settings, "SAML2_AUTH.JWT_EXP", default=60)  # default: 1 minute
        payload = {
            "email": target_user.email,
            "exp": (datetime.utcnow() +
                    timedelta(seconds=jwt_expiration)).timestamp()
        }
        jwt_token = jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm).decode("ascii")
        query = f"?token={jwt_token}"

        frontend_url = dictor(settings, "SAML2_AUTH.FRONTEND_URL", default=next_url)

        return HttpResponseRedirect(frontend_url + query)

    if target_user.is_active:
        model_backend = "django.contrib.auth.backends.ModelBackend"
        login(request, target_user, model_backend)

        after_login_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.AFTER_LOGIN")
        if after_login_trigger:
            run_hook(after_login_trigger, request.session, user_identity)
    else:
        raise SAMLAuthError("The target user is inactive.", extra={
            "exc_type": Exception,
            "error_code": INACTIVE_USER,
            "reason": "User is inactive.",
            "status_code": 500
        })

    if is_new_user:
        try:
            return render(request, "django_saml2_auth/welcome.html", {"user": request.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


@exception_handler
def signin(request: HttpRequest):
    next_url = request.GET.get("next") or get_default_next_url()

    try:
        if "next=" in unquote(next_url):
            parsed_next_url = urlparse.parse_qs(urlparse.urlparse(unquote(next_url)).query)
            next_url = dictor(parsed_next_url, "next.0")
    except:
        next_url = request.GET.get("next") or get_default_next_url()

    # Only permit signin requests where the next_url is a safe URL
    allowed_hosts = set(dictor(settings, "SAML2_AUTH.ALLOWED_REDIRECT_HOSTS", default=[]))
    if parse_version(get_version()) >= parse_version("2.0"):
        url_ok = is_safe_url(next_url, allowed_hosts)
    else:
        url_ok = is_safe_url(next_url)

    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))

    request.session["login_next_url"] = next_url

    saml_client = get_saml_client(get_assertion_url(request), acs)
    _, info = saml_client.prepare_for_authenticate(relay_state=next_url)

    redirect_url = None

    if "Location" in info["headers"]:
        redirect_url = info["headers"]["Location"]

    return HttpResponseRedirect(redirect_url)


@exception_handler
def signout(request: HttpRequest):
    logout(request)
    return render(request, "django_saml2_auth/signout.html")
