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
import re
class CustomUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        max_length=100, min_length=8, 
        style={'input_type':'password'}, write_only=True
        )
    class Meta:
        model = User
        fields = [
            'email', 'entry', 'password', 'name', 
            'country', 'password2', 'phone_number', 'user_id'
            ]
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
        if len(password) < 8 or password.lower() == password\
            or password.upper() == password or password.isalnum()\
            or not any(i.isdigit() for i in password):
            raise serializers.ValidationError({
                'password':'Your Password Is Weak',
                'Hint': 'Min. 8 characters, 1 letter, 1 number and 1 special character'
            })

        user.set_password(password)
        user.entry ='Tenant'
        user.is_active = True
        user.save()
        
        # room = Room.objects.create(user=user)
        # room.save()
        return user 
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False)

    class Meta:
        ref_name = "my_login"

    def __str__(self):
        return self.email

class CustomPasswordResetSerializer(serializers.Serializer):
    password =  serializers.CharField(
        max_length=100, min_length=8, 
        style={'input_type':'password'}, 
        write_only=True
        )
    comfirm_password = serializers.CharField(
        max_length=100, min_length=8, 
        style={'input_type':'password'}, 
        write_only=True
        )



"""Serializer which gets access token from Google
"""
class GetAcessTokenSerializer(serializers.Serializer):
    code = serializers.CharField()
   

class VerifyCodeSerializer(serializers.Serializer):

    class Meta:
        model = VerifyCode
        fields = "__all__"

class AgentSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = [
            'email', 'entry', 'password', 'name', 
            'country', 'password2', 'phone_number', 
            'home_address', 'user_id'
            ]
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
        if len(password) < 8 or password.lower() == password\
            or password.upper() == password or password.isalnum()\
            or not any(i.isdigit() for i in password):
            raise serializers.ValidationError({
                'password':'your password is weak',
                'Hint': 'It must be alphanumeric, must contain an Upper and Lower case character and minimum of 8 characters long '
            })
        user.set_password(password)
        user.entry = 'Agent'
        user.is_active = True
        user.save()
        return user 



class GenrateOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


    def __str__(self):
        return self.email