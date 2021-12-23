import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_KEY = "SECRET"
DEBUG = True
ALLOWED_HOSTS = []
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_saml2_auth",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "django_saml2_auth.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR + "/templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]
WSGI_APPLICATION = "django_saml2_auth.wsgi.application"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
    }
}
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
SAML2_AUTH = {
    "DEFAULT_NEXT_URL": "http://app.example.com/account/login",
    "CREATE_USER": True,
    "NEW_USER_PROFILE": {
        "USER_GROUPS": [],
        "ACTIVE_STATUS": True,
        "STAFF_STATUS": False,
        "SUPERUSER_STATUS": False
    },
    "ATTRIBUTES_MAP": {
        "email": "user.email",
        "username": "user.username",
        "first_name": "user.first_name",
        "last_name": "user.last_name",
        "token": "token"
    },
    "TRIGGER": {
        "BEFORE_LOGIN": "django_saml2_auth.tests.test_user.saml_user_setup",
        "GET_METADATA_AUTO_CONF_URLS": "django_saml2_auth.tests.test_saml.get_metadata_auto_conf_urls"
    },
    "ASSERTION_URL": "https://api.example.com",
    "ENTITY_ID": "https://api.example.com/sso/acs/",
    "NAME_ID_FORMAT": "user.email",
    "USE_JWT": True,
    "JWT_SECRET": "JWT_SECRET",
    "JWT_EXP": 60,
    "JWT_ALGORITHM": "HS256",
    "FRONTEND_URL": "https://app.example.com/account/login/saml",
    "LOGIN_CASE_SENSITIVE": False,
    "WANT_ASSERTIONS_SIGNED": True,
    "WANT_RESPONSE_SIGNED": True,
    "ALLOWED_REDIRECT_HOSTS": ["https://app.example.com",
                               "https://api.example.com",
                               "https://example.com"],
    "TOKEN_REQUIRED": True
}
