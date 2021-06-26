from entity.api import BaseEntityListView
from authentication.serializers import UserCreateAccountSerializer
from authentication.serializers import ObtainPairSerializerWithEmail

from rest_framework_simplejwt.views import TokenObtainPairView


class CreateAccount(BaseEntityListView):
    http_method_names = ['post']
    serializer = UserCreateAccountSerializer


class ObtainPairViewWithEmail(TokenObtainPairView):
    """
    Inherits from TokenObtainPairView to override the serializer class.
    Thus making authentication with email instead of username possible.
    """
    serializer_class = ObtainPairSerializerWithEmail
