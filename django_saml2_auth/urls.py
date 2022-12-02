from django.conf.urls import url
from django.urls import path
from . import views

app_name = 'django_saml2_auth'

urlpatterns = [
    path("<uuid:metadata_id>/acs/", views.acs, name="acs"),
    path(
        "<uuid:metadata_id>/load_metadata/",
        views.load_metadata,
        name="load_metadata",
    ),
    url(r'^welcome/$', views.welcome, name="welcome"),
    url(r'^denied/$', views.denied, name="denied"),
]
