from django.conf.urls import url, patterns


app_name = 'django_saml2_auth'

urlpatterns = patterns(
    'django_saml2_auth.views',
    url(r'^acs/$', "acs", name="acs"),
    url(r'^welcome/$', "welcome", name="welcome"),
    url(r'^denied/$', "denied", name="denied"),
)
