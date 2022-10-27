from os import access
from django.db import models

from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from django.conf import settings

class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'twitter': 'twitter', 'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def refresh_token(self):
        refresh = RefreshToken.for_user(self)
        decodeJTW = jwt.decode(str(refresh), settings.SECRET_KEY, algorithms=["HS256"])

        #decodeJTW['iat'] = '1590917498'
        #decodeJTW['name'] = 'marof'
        #decodeJTW['date'] = '2020-05-31'
        decodeJTW['name'] = self.username
        decodeJTW['email'] = self.email
        decodeJTW['id'] = self.id
        #token['password'] = user.password
        #decodeJTW['role'] = self.role

        #encode
        refresh = jwt.encode(decodeJTW, settings.SECRET_KEY, algorithm="HS256")
        refresh = refresh.decode('UTF-8')
        # return {
        #     'refresh': str(refresh),
        #     'access': str(refresh.access_token)
        # }
        return str(refresh)

    def access_token(self):
        refresh = RefreshToken.for_user(self)
        access_token = refresh.access_token

        decodeJTW = jwt.decode(str(access_token), settings.SECRET_KEY, algorithms=["HS256"])

        #decodeJTW['iat'] = '1590917498'
        #decodeJTW['name'] = 'marof'
        #decodeJTW['date'] = '2020-05-31'
        decodeJTW['name'] = self.username
        decodeJTW['email'] = self.email
        decodeJTW['id'] = self.id
        #token['password'] = user.password
        #decodeJTW['role'] = self.role

        #encode
        access = jwt.encode(decodeJTW, settings.SECRET_KEY, algorithm="HS256")
        access = access.decode('UTF-8')
        return str(access)