from dataclasses import fields
from pyexpat import model
from random import choice, choices
from re import U
from django.forms import CharField
from django.shortcuts import redirect
from .models import User, VerifyCode
import requests
from rest_framework import serializers
from rest_auth.serializers import PasswordResetSerializer
from django_countries.fields import CountryField
from django.contrib import messages
from message.models import Room
from transaction.models import Rooms
class CustomUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(max_length=100, min_length=8, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'entry', 'password', 'name', 'country', 'password2', 'phone_number', 'user_id']
        extra_kwargs = {
            'password':{ 
                'write_only':True
            },
            'password2': {
                'write_only':True
            
            },
        }          
    def save(self):
        user = User(
            email=self.validated_data['email'],
            name=self.validated_data['name'],
            country=self.validated_data['country'],
            phone_number=self.validated_data['phone_number'],     
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if password != password2:
            raise serializers.ValidationError({'password':'Passwords must match.'})
        user.set_password(password)
        user.entry ='Tenant'
        user.is_active = True
        user.save()
        try:
            Rooms.objects.get(user=user)
        except Exception as e:
            Rooms.objects.create(user=user)
        try:
             Room.objects.get(user=user)
        except Exception as e:
            Room.objects.create(user=user) 
        return user 
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False)

    class Meta:
        ref_name = "my_login"

    def __str__(self):
        return self.email

class CustomPasswordResetSerializer(PasswordResetSerializer):
    email = serializers.EmailField()
    phone_number = serializers.CharField()
    password = serializers.CharField(style={'input-type':'password'}, trim_whitespace=False)

"""Serializer which gets access token from Google
"""
class GetAcessTokenSerializer(serializers.Serializer):
    code = serializers.CharField()
   

class VerifyCodeSerializer(serializers.Serializer):

    class Meta:
        model = VerifyCode
        fields = "__all__"


#     email = serializers.EmailField(required=True)
#     def validate_email(self, email):
  
#         if User.objects.filter(email = email).count():
#             raise serializers.ValidationError(' This email has been registered ')
#             # Verify that the email number is legal
#         if not re.match(EMAIL_REGEX, email):
#             raise serializers.ValidationError(' Mailbox format error ')
#                 # Verification code sending frequency
#         one_minute_age = datetime.now() - timedelta(hours=0, minutes=1, seconds=0)
#         if VerifyCode.objects.filter(add_time__gt=one_minute_age, email=email).count():
#                 raise serializers.ValidationError(' Please send again in a minute ')
#         return email
class AgentSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'entry', 'password', 'name', 'country', 'password2', 'phone_number', 'home_address', 'user_id']
        extra_kwargs = {
            'password2': {
                'write_only':True
            },
        }
    def save(self):
        user = User(
            email=self.validated_data['email'],
            name=self.validated_data['name'],
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
        user.is_active = True
        user.save()
        return user 
