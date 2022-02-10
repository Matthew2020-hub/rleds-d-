from dataclasses import fields
from django.forms import CharField, models
from django.shortcuts import redirect
import requests
from rest_framework import serializers
from django_countries.fields import CountryField
from rest_auth.serializers import PasswordResetSerializer
from userAuthentication.models import User

class AgentSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'entry', 'password', 'first_name', 'last_name', 'country', 'password2', 'phone_number', 'home_address', 'user_id']
        extra_kwargs = {
            'password2': {
                'write_only':True
            },
        }
    def save(self):
        user = User(
            email=self.validated_data['email'],
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
            country=self.validated_data['country'],
            phone_number=self.validated_data['phone_number'], 
            home_address=self.validated_data['home_address'],     
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if password != password2:
            raise serializers.ValidationError({'password':'Passwords must match.'})
        user.set_password(password)
        user.entry = 'Agent'
        user.save()
        return user 


class AgentLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False)

    def __str__(self):
        return self.email

class SocialSerializer(serializers.Serializer):
    """
    Serializer which accepts an OAuth2 access token.
    """
    access_token = serializers.CharField()

class CustomPasswordResetSerializer(PasswordResetSerializer):
    email = serializers.EmailField()
    phone_number = serializers.CharField()
    password = serializers.CharField(style={'input_type':'password'}, write_only=True)

class GetAcessTokenSerializer(serializers.Serializer):
    code = serializers.CharField()
   
