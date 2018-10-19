from pkg_resources import parse_version

from django import get_version
from django.conf import settings


def get_reverse(objs):
    # In order to support different django version, I have to do this
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse, NoReverseMatch
    else:
        from django.core.urlresolvers import reverse, NoReverseMatch
    if objs.__class__.__name__ not in ['list', 'tuple']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except NoReverseMatch:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))


def get_sp_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http',
        host=r.get_host(),
    )
