from django.db import IntegrityError
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import serializers as jwt_serializer
from password_strength import PasswordStats

from authentication.utils import generate_username
from badgeuser.models import BadgeUser


class ObtainPairSerializerWithEmail(jwt_serializer.TokenObtainPairSerializer):
    username_field = BadgeUser.EMAIL_FIELD


class UserCreateAccountSerializer(serializers.ModelSerializer):
    """
    Serializer used when creating the account of a MonkUser
    """

    password1 = serializers.CharField()
    password2 = serializers.CharField()

    class Meta:
        model = BadgeUser
        fields = ['email', 'password1', 'password2']

    def validate_password1(self, password1):
        if PasswordStats(password1).strength() < 0.5:
            raise serializers.ValidationError('Password too weak, try using weird characters or make it longer')
        if password1 == self.initial_data.get('password2'):
            return password1
        raise serializers.ValidationError('Passwords do not match')

    def create(self, validated_data):
        try:
            return BadgeUser.objects.create_user(username=generate_username(validated_data['email']),
                                                 email=validated_data['email'],
                                                 password=validated_data['password1'])
        except IntegrityError as e:
            raise serializers.ValidationError('Email already exist. Please select another.')

    def to_representation(self, instance):
        token = RefreshToken.for_user(instance)  # create token to log user in after successful account creation
        refresh_token = str(token)
        access_token = str(token.access_token)
        return {'refresh': refresh_token, 'access': access_token}
