from django.conf.urls import url

from django_saml2_auth.views import acs, welcome, denied

urlpatterns = [
    url(r'^acs/$', acs, name="acs"),
    url(r'^welcome/$', welcome, name="welcome"),
    url(r'^denied/$', denied, name="denied"),
]
