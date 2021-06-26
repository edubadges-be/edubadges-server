from django.conf.urls import url
from rest_framework_simplejwt.views import TokenRefreshView
from authentication.api import ObtainPairViewWithEmail

from authentication.api import CreateAccount

urlpatterns = [
    url('create-account$', CreateAccount.as_view(), name='auth-create-account'),
    url('token$', ObtainPairViewWithEmail.as_view(), name='auth-get-token'),
    url('token/refresh$', TokenRefreshView.as_view(), name='auth-refresh-token'),
]
