# Django SAML2 Authentication Made Easy

- Original Author  
    Fang Li

- Maintainer  
    Mostafa Moradian

- Version  
    Use 1.1.4 for Django \<=1.9, 2.x.x for Django \>= 1.9, Latest supported django version is 2.2. Version \>=3.0.0 is heavily refactored.

This project aims to provide a simple way to integrate SAML2 Authentication into your Django-powered app. Try it now, and get rid of the complicated configuration of SAML.

Any SAML2 based SSO (Single Sign-On) identity provider (IdP) with dynamic metadata configuration is supported by this Django plugin, for example Okta. The library also supports service provider-initiated SSO.

## When you raise an issue or PR

Please note this library is mission-critical and supports almost all django versions since 1.7. We need to be extremely careful when merging any changes.

The support for new versions of django are welcome and I'll make best effort to make it latest django compatible.

## Donate

We accept donations, but not in the form of money\! If you want to support us, make sure to give us a nice, shiny ![star](https://img.shields.io/github/stars/grafana/django-saml2-auth.svg?style=social&label=Star&maxAge=86400)\!

## Install

You can install this plugin via `pip`. Make sure you update `pip` to be able to install from git:

``` bash
# pip install git+https://github.com/loadimpact/django-saml2-auth.git@master#egg=django-saml2-auth
```

or from source:

``` bash
# git clone https://github.com/loadimpact/django-saml2-auth
# cd django-saml2-auth
# python setup.py install
```

`xmlsec` is also required by `pysaml2`, so it must be installed:

``` bash
// RPM-based distributions
# yum install xmlsec1
// DEB-based distributions
# apt-get install xmlsec1
// macOS
# brew install xmlsec1
```

[Windows binaries](https://www.zlatkovic.com/projects/libxml/index.html) are also available.

## What does this plugin do?

This plugin can act as a SAML authentication system for Django that supports IdP and SP-initiated SSO.

- For IdP-initiated SSO, the user should log in to their IdP platform (e.g. Okta), and click on the application that authorizes and redirects the user to the SP (your platform).
- For SP-initiated SSO, the user should first exist on your platform (either log in using method 1 or else) and then it can be configured to be redirected to the correct application on the IdP platform.

For IdP-initiated SSO, the user will be created if it doesn't exist, but for SP-initiated SSO, the user should exist in your platform for the code to detect and redirect them to the correct application on the IdP platform.

## How to use?

1. Once you have the library installed or in your `requirements.txt`, import the views module in your root `urls.py`:

    ```python
    import django_saml2_auth.views
    ```

2. Override the default login page in the root `urls.py` file, by adding these lines **BEFORE** any `urlpatterns`:

    ```python
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
    ```

3. Add `'django_saml2_auth'` to `INSTALLED_APPS` in your django `settings.py`:

    ```python
    INSTALLED_APPS = [
        '...',
        'django_saml2_auth',
    ]
    ```

4. In `settings.py`, add the SAML2 related configuration:

    Please note, the only required setting is **METADATA\_AUTO\_CONF\_URL** or the existence of a **GET\_METADATA\_AUTO\_CONF\_URLS** trigger function. The following block shows all required and optional configuration settings and their default values.

    ```python
    SAML2_AUTH = {
        # Metadata is required, choose either remote url or local file path
        'METADATA_AUTO_CONF_URL': '[The auto(dynamic) metadata configuration URL of SAML2]',
        'METADATA_LOCAL_FILE_PATH': '[The metadata configuration file path]',

        'DEBUG': False,  # Send debug information to a log file

        # Optional settings below
        'DEFAULT_NEXT_URL': '/admin',  # Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be overwritten if you have parameter ?next= specificed in the login URL.
        'CREATE_USER': True,  # Create a new Django user when a new user logs in. Defaults to True.
        'NEW_USER_PROFILE': {
            'USER_GROUPS': [],  # The default group name when a new user logs in
            'ACTIVE_STATUS': True,  # The default active status for new users
            'STAFF_STATUS': False,  # The staff status for new users
            'SUPERUSER_STATUS': False,  # The superuser status for new users
        },
        'ATTRIBUTES_MAP': {  # Change Email/UserName/FirstName/LastName to corresponding SAML2 userprofile attributes.
            'email': 'user.email',
            'username': 'user.username',
            'first_name': 'user.first_name',
            'last_name': 'user.last_name',
            'token': 'Token',  # Mandatory, can be unrequired if TOKEN_REQUIRED is False
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
        'JWT_ALGORITHM': 'HS256',  # JWT algorithm to sign the message with
        'JWT_SECRET': 'your.jwt.secret',  # JWT secret to sign the message with
        'JWT_PRIVATE_KEY': '--- YOUR PRIVATE KEY ---',  # Private key to sign the message with. The algorithm should be set to RSA256 or a more secure alternative.
        'JWT_PRIVATE_KEY_PASSPHRASE': 'your.passphrase',  # If your private key is encrypted, you might need to provide a passphrase for decryption
        'JWT_PUBLIC_KEY': '--- YOUR PUBLIC KEY ---',  # Public key to decode the signed JWT token
        'JWT_EXP': 60,  # JWT expiry time in seconds
        'FRONTEND_URL': 'https://myfrontendclient.com',  # Redirect URL for the client if you are using JWT auth with DRF. See explanation below
        'LOGIN_CASE_SENSITIVE': True,  # whether of not to get the user in case_sentive mode
        'WANT_ASSERTIONS_SIGNED': True,  # Require each assertion to be signed
        'WANT_RESPONSE_SIGNED': False,  # Require response to be signed
        'ACCEPTED_TIME_DIFF': None,  # Accepted time difference between your server and the Identity Provider
        'ALLOWED_REDIRECT_HOSTS': ["https://myfrontendclient.com"], # Allowed hosts to redirect to using the ?next parameter
        'TOKEN_REQUIRED': True,  # Whether or not to require the token parameter in the SAML assertion
    }
    ```

5. In your SAML2 SSO identity provider, set the Single-sign-on URL and Audience URI (SP Entity ID) to <http://your-domain/saml2_auth/acs/>

### Explanation
| **Field name**                              | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                             | **Data type(s)** | **Default value(s)**                                                                                                                     | **Example**                                              |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| **METADATA\_AUTO\_CONF\_URL**               | Auto SAML2 metadata configuration URL                                                                                                                                                                                                                                                                                                                                                                                                                       | `str`            | `None`                                                                                                                                   | `https://ORG.okta.com/app/APP-ID/sso/saml/metadata`      |
| **METADATA\_LOCAL\_FILE\_PATH**             | SAML2 metadata configuration file path                                                                                                                                                                                                                                                                                                                                                                                                                      | `str`            | `None`                                                                                                                                   | `/path/to/the/metadata.xml`                              |
| **DEBUG**                                   | Send debug information to a log file                                                                                                                                                                                                                                                                                                                                                                                                                        | `bool`           | `False`                                                                                                                                  |                                                          |
| **DEFAULT\_NEXT\_URL**                      | Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be overwritten if you have parameter `?next=` specificed in the login URL.                                                                                                                                                                                                                                                                         | `str`            | `admin:index`                                                                                                                            | `https://app.example.com/account/login`                  |
| **CREATE\_USER**                            | Determines if a new Django user should be created for new users                                                                                                                                                                                                                                                                                                                                                                                             | `bool`           | `True`                                                                                                                                   |                                                          |
| **NEW\_USER\_PROFILE**                      | Default settings for newly created users                                                                                                                                                                                                                                                                                                                                                                                                                    | `dict`           | `{'USER_GROUPS': [], 'ACTIVE_STATUS': True, 'STAFF_STATUS': False, 'SUPERUSER_STATUS': False}`                                           |                                                          |
| **ATTRIBUTES\_MAP**                         | Mapping of Django user attributes to SAML2 user attributes                                                                                                                                                                                                                                                                                                                                                                                                  | `dict`           | `{'email': 'user.email', 'username': 'user.username', 'first_name': 'user.first_name', 'last_name': 'user.last_name', 'token': 'token'}` | `{'your.field': 'SAML.field'}`                           |
| **TOKEN\_REQUIRED**                         | Set this to `False` if you don't require the token parameter in the SAML assertion (in the attributes map)                                                                                                                                                                                                                                                                                                                                                  | `bool`           | `True`                                                                                                                                   |                                                          |
| **TRIGGER**                                 | Hooks to trigger additional actions during user login and creation flows. These `TRIGGER` hooks are strings containing a [dotted module name](https://docs.python.org/3/tutorial/modules.html#packages) which point to a method to be called. The referenced method should accept a single argument: a dictionary of attributes and values sent by the identity provider, representing the user's identity. Triggers will be executed only if they are set. | `dict`           | `{}`                                                                                                                                     |                                                          |
| **TRIGGER.CREATE\_USER**                    | A method to be called upon new user creation. This method will be called before the new user is logged in and after the user's record is created. This method should accept ONE parameter of user dict.                                                                                                                                                                                                                                                     | `str`            | `None`                                                                                                                                   | `my_app.models.users.create`                             |
| **TRIGGER.BEFORE\_LOGIN**                   | A method to be called when an existing user logs in. This method will be called before the user is logged in and after the SAML2 identity provider returns user attributes. This method should accept ONE parameter of user dict.                                                                                                                                                                                                                           | `str`            | `None`                                                                                                                                   | `my_app.models.users.before_login`                       |
| **TRIGGER.AFTER\_LOGIN**                    | A method to be called when an existing user logs in. This method will be called after the user is logged in and after the SAML2 identity provider returns user attributes. This method should accept TWO parameters of session and user dict.                                                                                                                                                                                                               | `str`            | `None`                                                                                                                                   | `my_app.models.users.after_login`                        |
| **TRIGGER.GET\_METADATA\_AUTO\_CONF\_URLS** | A hook function that returns a list of metadata Autoconf URLs. This can override the `METADATA_AUTO_CONF_URL` to enumerate all existing metadata autoconf URLs.                                                                                                                                                                                                                                                                                             | `str`            | `None`                                                                                                                                   | `my_app.models.users.get_metadata_autoconf_urls`         |
| **ASSERTION\_URL**                          | A URL to validate incoming SAML responses against. By default, `django-saml2-auth` will validate the SAML response's Service Provider address against the actual HTTP request's host and scheme. If this value is set, it will validate against `ASSERTION_URL` instead - perfect for when Django is running behind a reverse proxy.                                                                                                                        | `str`            | `https://example.com`                                                                                                                    |                                                          |
| **ENTITY\_ID**                              | The optional entity ID string to be passed in the 'Issuer' element of authentication request, if required by the IDP.                                                                                                                                                                                                                                                                                                                                       | `str`            | `None`                                                                                                                                   | `https://exmaple.com/sso/acs`                            |
| **NAME\_ID\_FORMAT**                        | Set to the string `'None'`, to exclude sending the `'Format'` property of the `'NameIDPolicy'` element in authentication requests.                                                                                                                                                                                                                                                                                                                          | `str`            | `<urn:oasis:names:tc:SAML:2.0:nameid-format:transient>`                                                                                  |                                                          |
| **USE\_JWT**                                | Set this to the boolean `True` if you are using Django with JWT authentication                                                                                                                                                                                                                                                                                                                                                                              | `bool`           | `False`                                                                                                                                  |                                                          |
| **JWT\_ALGORITHM**                          | JWT algorithm (str) to sign the message with: [supported algorithms](https://pyjwt.readthedocs.io/en/stable/algorithms.html).                                                                                                                                                                                                                                                                                                                               | `str`            | `HS512` or `RS512`                                                                                                                       |                                                          |
| **JWT\_SECRET**                             | JWT secret to sign the message if an HMAC is used with the SHA hash algorithm (`HS*`).                                                                                                                                                                                                                                                                                                                                                                      | `str`            | `None`                                                                                                                                   |                                                          |
| **JWT\_PRIVATE\_KEY**                       | Private key (str) to sign the message with. The algorithm should be set to `RSA256` or a more secure alternative.                                                                                                                                                                                                                                                                                                                                           | `str` or `bytes` | `--- YOUR PRIVATE KEY ---`                                                                                                               |                                                          |
| **JWT\_PRIVATE\_KEY\_PASSPHRASE**           | If your private key is encrypted, you must provide a passphrase for decryption.                                                                                                                                                                                                                                                                                                                                                                             | `str` or `bytes` | `None`                                                                                                                                   |                                                          |
| **JWT\_PUBLIC\_KEY**                        | Public key to decode the signed JWT token.                                                                                                                                                                                                                                                                                                                                                                                                                  | `str` or `bytes` | `'--- YOUR PUBLIC KEY ---'`                                                                                                              |                                                          |
| **JWT\_EXP**                                | JWT expiry time in seconds                                                                                                                                                                                                                                                                                                                                                                                                                                  | `int`            | 60                                                                                                                                       |                                                          |
| **FRONTEND\_URL**                           | If `USE_JWT` is `True`, you should set the URL to where your frontend is located (will default to `DEFAULT_NEXT_URL` if you fail to do so). Once the client is authenticated through the SAML SSO, your client is redirected to the `FRONTEND_URL` with the JWT token as `token` query parameter. Example: `https://app.example.com/?&token=<your.jwt.token`. With the token, your SPA can now authenticate with your API.                                  | `str`            | `admin:index`                                                                                                                            |                                                          |
| **WANT\_ASSERTIONS\_SIGNED**                | Set this to `False` if your provider doesn't sign each assertion.                                                                                                                                                                                                                                                                                                                                                                                           | `bool`           | `True`                                                                                                                                   |                                                          |
| **WANT\_RESPONSE\_SIGNED**                  | Set this to `False` if you don't want your provider to sign the response.                                                                                                                                                                                                                                                                                                                                                                                   | `bool`           | `True`                                                                                                                                   |                                                          |
| **ACCEPTED\_TIME\_DIFF**                    | Sets the [accepted time diff](https://pysaml2.readthedocs.io/en/latest/howto/config.html#accepted-time-diff) in seconds                                                                                                                                                                                                                                                                                                                                     | `int` or `None`  | `None`                                                                                                                                   |                                                          |
| **ALLOWED\_REDIRECT\_HOSTS**                | Allowed hosts to redirect to using the `?next=` parameter                                                                                                                                                                                                                                                                                                                                                                                                   | `list`           | `[]`                                                                                                                                     | `['https://app.example.com', 'https://api.exmaple.com']` |

## JWT Signing Algorithm and Settings

Both symmetric and asymmetric signing functions are [supported](https://pyjwt.readthedocs.io/en/stable/algorithms.html). If you want to use symmetric signing using a secret key, use either of the following algorithms plus a secret key:

- HS256
- HS384
- HS512

```python
{
    ...
    'USE_JWT': True,
    'JWT_ALGORITHM': 'HS256',
    'JWT_SECRET': 'YOU.ULTRA.SECURE.SECRET',
    ...
}
```

Otherwise if you want to use your PKI key-pair to sign JWT tokens, use either of the following algorithms and then set the following fields:

- RS256
- RS384
- RS512
- ES256
- ES256K
- ES384
- ES521
- ES512
- PS256
- PS384
- PS512
- EdDSA

```python
{
    ...
    'USE_JWT': True,
    'JWT_ALGORITHM': 'RS256',
    'JWT_PRIVATE_KEY': '--- YOUR PRIVATE KEY ---',
    'JWT_PRIVATE_KEY_PASSPHRASE': 'your.passphrase',  # Optional, if your private key is encrypted
    'JWT_PUBLIC_KEY': '--- YOUR PUBLIC KEY ---',
    ...
}
```

*Note:* If both PKI fields and `JWT_SECRET` are defined, the `JWT_ALGORITHM` decides which method to use for signing tokens.

## Customize

The default permission `denied`, `error` and user `welcome` page can be overridden.

To override these pages put a template named 'django\_saml2\_auth/error.html', 'django\_saml2\_auth/welcome.html' or 'django\_saml2\_auth/denied.html' in your project's template folder.

If a 'django\_saml2\_auth/welcome.html' template exists, that page will be shown to the user upon login instead of the user being redirected to the previous visited page. This welcome page can contain some first-visit notes and welcome words. The [Django user object](https://docs.djangoproject.com/en/1.9/ref/contrib/auth/#django.contrib.auth.models.User) is available within the template as the `user` template variable.

To enable a logout page, add the following lines to `urls.py`, before any `urlpatterns`:

```python
# The following line will replace the default user logout with the signout page (optional)
url(r'^accounts/logout/$', django_saml2_auth.views.signout),

# The following line will replace the default admin user logout with the signout page (optional)
url(r'^admin/logout/$', django_saml2_auth.views.signout),
```

To override the built in signout page put a template named 'django\_saml2\_auth/signout.html' in your project's template folder.

If your SAML2 identity provider uses user attribute names other than the defaults listed in the `settings.py` `ATTRIBUTES_MAP`, update them in `settings.py`.

## For Okta Users

I created this plugin originally for Okta. The `METADATA_AUTO_CONF_URL` needed in `settings.py` can be found in the Okta Web UI by navigating to the SAML2 app's `Sign On` tab. In the `Settings` box, you should see:

    Identity Provider metadata is available if this application supports dynamic configuration.

The `Identity Provider metadata` link is the `METADATA_AUTO_CONF_URL`.

More information can be found in the [Okta Developer Documentation](https://developer.okta.com/docs/guides/saml-application-setup/overview/).

## How to Contribute

1. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
2. Fork [the repository](http://github.com/loadimpact/django-saml2-auth) on GitHub to start making your changes to the **master** branch (or branch off of it).
3. Write a test which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to [AUTHORS](https://github.com/grafana/django-saml2-auth/blob/master/AUTHORS.md).

## Release Log

3.3.0: Add support for PKI in JWT

3.2.0: Update dependencies (#22)

3.1.0: Make `token` field optional in the attribute statement by introducing `REQUIRE_TOKEN` settings (default: `True`)

3.0.1: Minor fixes

3.0.0: Extensive refactoring of the library (check the commit logs) - incompatible with previous versions

2.3.0: Merge of PRs plus bugfixes and (manual) testing

2.2.1: Fixed is\_safe\_url parameters issue for django 2.1

2.2.0: ADFS SAML compatibility and fixed some issue for Django2.0

2.1.2: Merged \#35

2.1.1: Added ASSERTION\_URL in settings.

2.1.0: Add DEFAULT\_NEXT\_URL. Issue \#19.

2.0.4: Fixed compatibility with Windows.

2.0.3: Fixed a vulnerabilities in the login flow, thanks qwrrty.

2.0.1: Add support for Django 1.10

1.1.4: Fixed urllib bug

1.1.2: Added support for Python 2.7/3.x

1.1.0: Added support for Django 1.6/1.7/1.8/1.9

1.0.4: Fixed English grammar mistakes
