import random
import string
import base64

from hashlib import md5
from django.contrib.auth import get_user_model


def get_user_by_natural_key(user_id):
    """
    Function used by Graphene's JSONWebTokenMiddleware to return a user
    from the JWT payload's 'user_id' variable (i.e the PK)
    """
    return get_user_model().objects.get(pk=user_id)


def generate_username(email):
    """Username generator copied from Badgr"""
    # md5 hash the email and then encode as base64 to take up only 25 characters
    salted_email = (email + ''.join(random.choice(string.ascii_lowercase) for i in range(64))).encode('utf-8')
    hashed = str(base64.b64encode(md5(salted_email).hexdigest().encode('utf-8')), 'utf-8')
    return "monk{}".format(hashed[:25])
