from django.urls import path
from . import views

app_name = 'django_saml2_auth'

urlpatterns = [
    path(r'acs/', views.acs, name="acs"),
    path(r'welcome/', views.welcome, name="welcome"),
    path(r'denied/', views.denied, name="denied"),
]
