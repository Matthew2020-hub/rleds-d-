from dataclasses import fields
from random import choice, choices
from re import U
from django.forms import CharField
from django.shortcuts import redirect
from .models import User
import requests
from rest_framework import serializers
from rest_auth.serializers import PasswordResetSerializer
from django_countries.fields import CountryField

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['is_tenant', 'is_agent']
class CustomUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    # entry = serializers.ChoiceField(choices='tenant')
    class Meta:
        model = User
        fields = ['email', 'entry', 'password', 'first_name', 'last_name', 'country', 'password2', 'phone_number', 'user_id']
        extra_kwargs = {
            'password2': {
                'write_only':True
            },
        }
    # def validate(self, attrs):
    #     email = attrs.get('email', '')
    #     if email.isalnum():
    #         raise serializers.ValidationError(
    #             'Email should only contain alphanumeric characters'
    #         )
    #         return attrs
            
    def save(self):
        user = User(
            email=self.validated_data['email'],
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
            country=self.validated_data['country'],
            phone_number=self.validated_data['phone_number'],     
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if password != password2:
            raise serializers.ValidationError({'password':'Passwords must match.'})
        user.set_password(password)
        user.entry ='Tenant'
        user.save()
       
        return user 
class LoginUserSerializer(serializers.Serializer):
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
    password = serializers.CharField(style={'input-type':'password'}, trim_whitespace=False)



class GetAcessTokenSerializer(serializers.Serializer):
    code = serializers.CharField()
   
