#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib.parse as urlparse
from urllib.parse import unquote

from dictor import dictor
from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.http import is_safe_url
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version

from .errors import *
from .exceptions import SAMLAuthError
from .utils import (create_jwt_token, decode_saml_response, exception_handler,
                    extract_user_identity, get_assertion_url,
                    get_default_next_url, get_or_create_user, get_reverse,
                    get_saml_client, run_hook)


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

    authn_response = decode_saml_response(request, acs)
    user_identity = authn_response.get_identity()
    user = extract_user_identity(user_identity)

    next_url = request.session.get("login_next_url") or get_default_next_url()
    # If relayState params is passed, use that else consider the previous "next_url"
    next_url = request.POST.get("RelayState") or next_url

    is_new_user, target_user = get_or_create_user(user)

    before_login_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.BEFORE_LOGIN")
    if before_login_trigger:
        run_hook(before_login_trigger, user)

    request.session.flush()

    use_jwt = dictor(settings, "SAML2_AUTH.USE_JWT", default=False)
    if use_jwt and target_user.is_active:
        jwt_token = create_jwt_token(target_user)
        # Use JWT auth to send token to frontend
        query = f"?token={jwt_token}"

        frontend_url = dictor(settings, "SAML2_AUTH.FRONTEND_URL", default=next_url)

        return HttpResponseRedirect(frontend_url + query)

    if target_user.is_active:
        model_backend = "django.contrib.auth.backends.ModelBackend"
        login(request, target_user, model_backend)

        after_login_trigger = dictor(settings, "SAML2_AUTH.TRIGGER.AFTER_LOGIN")
        if after_login_trigger:
            run_hook(after_login_trigger, request.session, user)
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
