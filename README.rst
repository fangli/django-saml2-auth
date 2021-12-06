=====================================
Django SAML2 Authentication Made Easy
=====================================

:Original Author: Fang Li
:Maintainer: Mostafa Moradian
:Version: Use 1.1.4 for Django <=1.9, 2.x.x for Django >= 1.9, Latest supported django version is 2.2. Version >=3.0.0 is heavily refactored.

This project aims to provide a simple way to integrate SAML2 Authentication into your Django-powered app. Try it now, and get rid of the complicated configuration of SAML.

Any SAML2 based SSO (Single Sign-On) identity provider (IdP) with dynamic metadata configuration is supported by this Django plugin, for example Okta. The library also supports service provider-initiated SSO.


When you raise an issue or PR
=============================

Please note this library is mission-critical and supports almost all django versions since 1.7. We need to be extremely careful when merging any changes.

The support for new versions of django are welcome and I'll make best effort to make it latest django compatible.


Donate
======

We accept donations, but not in the form of money! If you want to support us, make sure to give us a nice, shiny |star|!

.. |star| image:: https://img.shields.io/github/stars/loadimpact/django-saml2-auth.svg?style=social&label=Star&maxAge=86400


Install
=======

You can install this plugin via ``pip``. Make sure you update ``pip`` to be able to install from git:

.. code-block:: bash

    # pip install git+https://github.com/loadimpact/django-saml2-auth.git@master#egg=django-saml2-auth

or from source:

.. code-block:: bash

    # git clone https://github.com/loadimpact/django-saml2-auth
    # cd django-saml2-auth
    # python setup.py install

``xmlsec`` is also required by ``pysaml2``, so it must be installed:

.. code-block:: bash

    // RPM-based distributions
    # yum install xmlsec1
    // DEB-based distributions
    # apt-get install xmlsec1
    // macOS
    # brew install xmlsec1

`Windows binaries <https://www.zlatkovic.com/projects/libxml/index.html>`_ are also available.


What does this plugin do?
=========================

This plugin can act as a SAML authentication system for Django that supports IdP and SP-initiated SSO.

- For IdP-initiated SSO, the user should log in to their IdP platform (e.g. Okta), and click on the application that authorizes and redirects the user to the SP (your platform).
- For SP-initiated SSO, the user should first exist on your platform (either log in using method 1 or else) and then it can be configured to be redirected to the correct application on the IdP platform.

For IdP-initiated SSO, the user will be created if it doesn't exist, but for SP-initiated SSO, the user should exist in your platform for the code to detect and redirect them to the correct application on the IdP platform.


How to use?
===========

#. Once you have the library installed or in your ``requirements.txt``, import the views module in your root ``urls.py``:

    .. code-block:: python

        import django_saml2_auth.views

#. Override the default login page in the root ``urls.py`` file, by adding these lines **BEFORE** any ``urlpatterns``:

    .. code-block:: python

        # These are the SAML2 related URLs. You can change "^saml2_auth/" regex to
        # any path you want, like "^sso/", "^sso_auth/", "^sso_login/", etc. (required)
        url(r'^sso/', include('django_saml2_auth.urls')),

        # The following line will replace the default user login with SAML2 (optional)
        # If you want to specific the after-login-redirect-URL, use parameter "?next=/the/path/you/want"
        # with this view.
        url(r'^accounts/login/$', django_saml2_auth.views.signin),

        # The following line will replace the admin login with SAML2 (optional)
        # If you want to specific the after-login-redirect-URL, use parameter "?next=/the/path/you/want"
        # with this view.
        url(r'^admin/login/$', django_saml2_auth.views.signin),

#. Add ``'django_saml2_auth'`` to ``INSTALLED_APPS`` in your django ``settings.py``:

    .. code-block:: python

        INSTALLED_APPS = [
            '...',
            'django_saml2_auth',
        ]

#. In ``settings.py``, add the SAML2 related configuration:

    Please note, the only required setting is **METADATA_AUTO_CONF_URL** or the existence of a **GET_METADATA_AUTO_CONF_URLS** trigger function.
    The following block shows all required and optional configuration settings and their default values.

    .. code-block:: python

        SAML2_AUTH = {
            # Metadata is required, choose either remote url or local file path
            'METADATA_AUTO_CONF_URL': '[The auto(dynamic) metadata configuration URL of SAML2]',
            'METADATA_LOCAL_FILE_PATH': '[The metadata configuration file path]',

            'DEBUG': False,  # Send debug information to log file

            # Optional settings below
            'DEFAULT_NEXT_URL': '/admin',  # Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be overwritten if you have parameter ?next= specificed in the login URL.
            'CREATE_USER': 'TRUE',  # Create a new Django user when a new user logs in. Defaults to True.
            'NEW_USER_PROFILE': {
                'USER_GROUPS': [],  # The default group name when a new user logs in
                'ACTIVE_STATUS': True,  # The default active status for new users
                'STAFF_STATUS': False,  # The staff status for new users
                'SUPERUSER_STATUS': False,  # The superuser status for new users
            },
            'ATTRIBUTES_MAP': {  # Change Email/UserName/FirstName/LastName to corresponding SAML2 userprofile attributes.
                'email': 'Email',
                'username': 'UserName',
                'first_name': 'FirstName',
                'last_name': 'LastName',
                'token': 'Token',  # Mandatory
                'groups': 'Groups',  # Optional
            },
            'GROUPS_MAP': {  # Optionally allow mapping SAML2 Groups to Django Groups
                'SAML Group Name': 'Django Group Name',
            },
            'TRIGGER': {
                'CREATE_USER': 'path.to.your.new.user.hook.method',
                'BEFORE_LOGIN': 'path.to.your.login.hook.method',
                'AFTER_LOGIN': 'path.to.your.after.login.hook.method',
                # This can override the METADATA_AUTO_CONF_URL to enumerate all existing metadata autoconf URLs
                'GET_METADATA_AUTO_CONF_URLS': 'path.to.your.after.metadata.conf.hook.method',
            },
            'ASSERTION_URL': 'https://mysite.com',  # Custom URL to validate incoming SAML requests against
            'ENTITY_ID': 'https://mysite.com/saml2_auth/acs/',  # Populates the Issuer element in authn request
            'NAME_ID_FORMAT': FormatString,  # Sets the Format property of authn NameIDPolicy element, e.g. 'user.email'
            'USE_JWT': True,  # Set this to True if you are running a Single Page Application (SPA) with Django Rest Framework (DRF), and are using JWT authentication to authorize client users
            'JWT_SECRET': 'your.jwt.secret',  # JWT secret to sign the message with
            'JWT_ALGORITHM': 'HS256',  # JWT algorithm to sign the message with
            'JWT_EXP': 60,  # JWT expiry time in seconds
            'FRONTEND_URL': 'https://myfrontendclient.com',  # Redirect URL for the client if you are using JWT auth with DRF. See explanation below
            'LOGIN_CASE_SENSITIVE': True,  # whether of not to get the user in case_sentive mode
            'WANT_ASSERTIONS_SIGNED': True,  # Require each assertion to be signed
            'WANT_RESPONSE_SIGNED': False,  # Require response to be signed
            'ALLOWED_REDIRECT_HOSTS': ["https://myfrontendclient.com"] # Allowed hosts to redirect to using the ?next parameter
        }

#. In your SAML2 SSO identity provider, set the Single-sign-on URL and Audience URI (SP Entity ID) to http://your-domain/saml2_auth/acs/


Explanation
-----------

**GET_METADATA_AUTO_CONF_URLS** hook is function that returns list of metadata autoconf URLs

**METADATA_AUTO_CONF_URL** Auto SAML2 metadata configuration URL

**METADATA_LOCAL_FILE_PATH** SAML2 metadata configuration file path

**DEBUG** Send debug information to log file (defaults to False)

**CREATE_USER** Determines if a new Django user should be created for new users

**NEW_USER_PROFILE** Default settings for newly created users

**ATTRIBUTES_MAP** Mapping of Django user attributes to SAML2 user attributes

**TRIGGER** Hooks to trigger additional actions during user login and creation
flows. These TRIGGER hooks are strings containing a `dotted module name <https://docs.python.org/3/tutorial/modules.html#packages>`_
which point to a method to be called. The referenced method should accept a
single argument which is a dictionary of attributes and values sent by the
identity provider, representing the user's identity.

**TRIGGER.CREATE_USER** A method to be called upon new user creation. This
method will be called before the new user is logged in and after the user's
record is created. This method should accept ONE parameter of user dict.

**TRIGGER.BEFORE_LOGIN** A method to be called when an existing user logs in.
This method will be called before the user is logged in and after user
attributes are returned by the SAML2 identity provider. This method should accept ONE parameter of user dict.

**TRIGGER.AFTER_LOGIN** A method to be called when an existing user logs in.
This method will be called after the user is logged in and after user
attributes are returned by the SAML2 identity provider. This method should accept TWO parameters of session and user dict.

**ASSERTION_URL** A URL to validate incoming SAML responses against. By default,
django-saml2-auth will validate the SAML response's Service Provider address
against the actual HTTP request's host and scheme. If this value is set, it
will validate against ASSERTION_URL instead - perfect for when django running
behind a reverse proxy.

**ENTITY_ID** The optional entity ID string to be passed in the 'Issuer' element of authn request, if required by the IDP.

**NAME_ID_FORMAT** Set to the string 'None', to exclude sending the 'Format' property of the 'NameIDPolicy' element in authn requests.
Default value if not specified is 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'.

**USE_JWT** Set this to the boolean True if you are using Django Rest Framework with JWT authentication

**FRONTEND_URL** If USE_JWT is True, you should set the URL of where your frontend is located (will default to DEFAULT_NEXT_URL if you fail to do so). Once the client is authenticated through the SAML/SSO, your client is redirected to the FRONTEND_URL with the user id (uid) and JWT token (token) as query parameters.
Example: 'https://myfrontendclient.com/?uid=<user id>&token=<jwt token>'
With these params your client can now authenticate with server resources.

**WANT_ASSERTIONS_SIGNED** Set this to the boolean False if your provider doesn't sign each assertion.

**WANT_RESPONSE_SIGNED** Set this to the boolean True if you require your provider to sign the response.

**ACCEPTED_TIME_DIFF** Sets the accepted time diff in seconds `PySaml2 Accepted Time Diff <https://pysaml2.readthedocs.io/en/latest/howto/config.html#accepted-time-diff>`_

Customize
=========

The default permission ``denied``, ``error`` and user ``welcome`` page can be overridden.

To override these pages put a template named 'django_saml2_auth/error.html', 'django_saml2_auth/welcome.html' or 'django_saml2_auth/denied.html' in your project's template folder.

If a 'django_saml2_auth/welcome.html' template exists, that page will be shown to the user upon login instead of the user being redirected to the previous visited page. This welcome page can contain some first-visit notes and welcome
words. The `Django user object <https://docs.djangoproject.com/en/1.9/ref/contrib/auth/#django.contrib.auth.models.User>`_ is available within the template as the ``user`` template variable.

To enable a logout page, add the following lines to ``urls.py``, before any ``urlpatterns``:

.. code-block:: python

    # The following line will replace the default user logout with the signout page (optional)
    url(r'^accounts/logout/$', django_saml2_auth.views.signout),

    # The following line will replace the default admin user logout with the signout page (optional)
    url(r'^admin/logout/$', django_saml2_auth.views.signout),

To override the built in signout page put a template named
'django_saml2_auth/signout.html' in your project's template folder.

If your SAML2 identity provider uses user attribute names other than the
defaults listed in the ``settings.py`` ``ATTRIBUTES_MAP``, update them in
``settings.py``.


For Okta Users
==============

I created this plugin originally for Okta. The ``METADATA_AUTO_CONF_URL`` needed in ``settings.py`` can be found in the Okta Web UI by navigating to the SAML2 app's ``Sign On`` tab. In the ``Settings`` box, you should see::

    Identity Provider metadata is available if this application supports dynamic configuration.

The ``Identity Provider metadata`` link is the ``METADATA_AUTO_CONF_URL``.

More information can be found in the `Okta Developer Documentation <https://developer.okta.com/docs/guides/saml-application-setup/overview/>`_.


How to Contribute
=================

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
#. Fork `the repository`_ on GitHub to start making your changes to the **master** branch (or branch off of it).
#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to AUTHORS_.

.. _`the repository`: http://github.com/loadimpact/django-saml2-auth
.. _AUTHORS: https://github.com/loadimpact/django-saml2-auth/blob/master/AUTHORS.rst


Release Log
===========

3.0.0 : Extensive refactoring of the library (check the commit logs) - incompatible with previous versions

2.3.0: Merge of PRs plus bugfixes and (manual) testing

2.2.1: Fixed is_safe_url parameters issue for django 2.1

2.2.0: ADFS SAML compatibility and fixed some issue for Django2.0

2.1.2: Merged #35

2.1.1: Added ASSERTION_URL in settings.

2.1.0: Add DEFAULT_NEXT_URL. Issue #19.

2.0.4: Fixed compatibility with Windows.

2.0.3: Fixed a vulnerabilities in the login flow, thanks qwrrty.

2.0.1: Add support for Django 1.10

1.1.4: Fixed urllib bug

1.1.2: Added support for Python 2.7/3.x

1.1.0: Added support for Django 1.6/1.7/1.8/1.9

1.0.4: Fixed English grammar mistakes
