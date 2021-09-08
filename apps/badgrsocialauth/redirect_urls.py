import importlib

from allauth.socialaccount import providers
from badgrsocialauth.views import BadgrSocialLogin, BadgrSocialEmailExists, BadgrSocialAccountVerifyEmail, \
    BadgrSocialLoginCancel, BadgrAccountConnected, ImpersonateUser
from badgrsocialauth.api import SamlLoginView
from django.conf.urls import url

urlpatterns = [
    url(r'^sociallogin', BadgrSocialLogin.as_view(permanent=False), name='socialaccount_login'),

    url(r'^socialaccounts/samllogin$', SamlLoginView.as_view(), name='v1_api_saml_login'),

    # Intercept allauth cancel login view
    url(r'^cancellogin', BadgrSocialLoginCancel.as_view(permanent=False), name='socialaccount_login_cancelled'),

    # Intercept allauth signup view (if account with given email already exists) and redirect to UI
    url(r'^emailexists', BadgrSocialEmailExists.as_view(permanent=False), name='socialaccount_signup'),

    # Intercept allauth email verification view and redirect to UI
    url(r'^verifyemail', BadgrSocialAccountVerifyEmail.as_view(permanent=False), name='account_email_verification_sent'),

    # Intercept allauth connections view (attached a new social account)
    url(r'^connected', BadgrAccountConnected.as_view(permanent=False), name='socialaccount_connections'),

    url(r'^impersonate/(?P<id>[^/]+)$', ImpersonateUser.as_view(), name='impersonate_user'),

]


for provider in providers.registry.get_list():
    try:
        prov_mod = importlib.import_module(provider.get_package() + '.urls')
    except ImportError:
        continue
    prov_urlpatterns = getattr(prov_mod, 'urlpatterns', None)
    if prov_urlpatterns:
        urlpatterns += prov_urlpatterns