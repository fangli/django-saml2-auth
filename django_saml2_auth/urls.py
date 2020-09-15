from django.urls import re_path as url

from . import views

app_name = 'django_saml2_auth'

urlpatterns = [
    url(r'^acs/$', views.acs, name="acs"),
    url(r'^welcome/$', views.welcome, name="welcome"),
    url(r'^denied/$', views.denied, name="denied"),
]
