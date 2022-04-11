from audioop import reverse
import email
from lib2to3.pgen2.tokenize import TokenError
from time import time
from django.shortcuts import render
from http.client import responses
from lib2to3.pgen2 import token
from multiprocessing import AuthenticationError
from os import access
import re
from django.forms import ValidationError
from django.shortcuts import render
from .serializers import (LoginSerializer, GetAcessTokenSerializer,
CustomPasswordResetSerializer, AgentSerializer, VerifyCodeSerializer, 
CustomUserSerializer, GenrateOTPSerializer)
from .models import User, VerifyCode
# from message.models import Room
from django.shortcuts import get_object_or_404
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_auth.views import LoginView as RestLoginView
from django.contrib.auth import logout, login
from django.utils.translation import gettext_lazy as _
from dev.settings import (
    SOCIAL_AUTH_GOOGLE_KEY, SOCIAL_AUTH_GOOGLE_SECRET, 
    redirect_uri, project_id
)
from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import redirect, render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
import requests
from rest_framework.exceptions import AuthenticationFailed
import jwt, datetime
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .utils import Util
from django.core.mail import send_mail
from django.utils.http import unquote
from django.contrib.auth import authenticate
from django.contrib import messages
from drf_yasg.utils import swagger_auto_schema
import os
import environ
import django.contrib.auth.password_validation as validators
from django.core.exceptions import ValidationError
from random import choice, random
# from twilio.rest import Client
# from dev.settings import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_NUMBER
from random import randint
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from mailjet_rest import Client
from datetime import time

env = environ.Env()
environ.Env.read_env('housefree.env')
from_email= os.environ.get('EMAIL_HOST_USER')

api_key = os.environ.get('MJ_API_KEY')
api_secret = os.environ.get('MJ_API_SECRET')      


TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_NUMBER = os.environ.get("TWILIO_NUMBER")





"""An endpoint to create user and to GET list of all users"""
class ListUserAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = CustomUserSerializer
    queryset = User.objects.filter(entry='Tenant')
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        check = User.objects.filter(entry='Tenant')
        return self.list(check)
class userRegistration(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes=[AllowAny]
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        user_token = Token.objects.get_or_create(user=user)
        
        context = {
            'token': user_token[0].key,
            'message': 'Check your email and verify',
            "data": serializer.data
    }
        return Response(context, status=status.HTTP_201_CREATED)



class agentRegistration(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def post(self, request):
        serializer = AgentSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
    
        email_verification_token = RefreshToken.for_user(user).access_token
        absurl = f'https://freehouses.herokuapp.com/api/v1/email-verify?token={email_verification_token}' 
        email_body = 'Hi '+ ' ' + user.name+':\n'+ 'Use link below to verify your email' '\n'+ absurl
        data = {
            'email_body': email_body,'to_email':user.email,
            'subject': 'Verify your email'
        }
        mailjet = Client(auth=(api_key, api_secret), version='v3.1')
        data = {
        'Messages': [
            {
            "From": {
                "Email": f"akinolatolulope24@gmail.com",
                "Name": "freehouse"
            },
            "To": [
                {
                "Email": f"{user.email}",
                "Name": f"{user.name}"
                }
            ],
            "Subject": "Email Verification",
            "TextPart": "Click on the below link to verify your Email!",
            "HTMLPart":  email_body
            }
        ]
        }

        result = mailjet.send.create(data=data)
        agent_token = Token.objects.get_or_create(user=user)
        context = {
            'token': agent_token[0].key,
            'message': 'Check your email and verify',
            "data": serializer.data
        }
       
        return Response(context, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@permission_classes([AllowAny])
def refreshToken( request, email):
    get_token = get_object_or_404(User, email=email)
    if get_token.is_verify is True:
        return Response("User's Email already verified", status=status.HTTP_208_ALREADY_REPORTED)
    email_verification_token = RefreshToken.for_user(get_token).access_token
    current_site = get_current_site(request).domain
    absurl = f'https://freehouses.herokuapp.com/api/v1/email-verify?token={email_verification_token}' 
    email_body = 'Hi '+ ' ' + get_token.name+':\n'+ 'Use link below to verify your email' '\n'+ absurl
    data = {
        'email_body': email_body,'to_email':get_token.email,
        'subject': 'Verify your email'
    }
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')
    data = {
    'Messages': [
        {
        "From": {
            "Email": f"akinolatolulope24@gmail.com",
            "Name": "freehouse"
        },
        "To": [
            {
            "Email": f"{get_token.email}",
            "Name": f"{get_token.name}"
            }
        ],
        "Subject": "Email Verification",
        "TextPart": "Click on the below link to verify your Email!",
        "HTMLPart":  email_body
        }
    ]
    }
    result = mailjet.send.create(data=data)
    return Response(result.json(), 
        status=status.HTTP_201_CREATED)

"""Verify user email endpoint"""
class VerifyEmail(APIView):
    permisssion_classes = [AllowAny]
    def get(self, request):
        token = request.GET.get('token')
        access_token_str = str(token)
        try:
            # access token verification
            access_token_obj = AccessToken(access_token_str) 
        except Exception as e:
            return Response(
        'No token Input or Token already expired', 
        status= status.HTTP_400_BAD_REQUEST
        )
        user_id = access_token_obj['user_id']
        user = get_object_or_404(User, user_id=user_id)
        if not user.is_verify:
            user.is_verify = True
            user.save()   
        return Response({
            'email': 'Email successfully activated, kindly return to the login page'}, 
            status=status.HTTP_200_OK
            )

"""An endpoint to GET a specific user, Update user info and delete a user's record"""
class ListUserAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = CustomUserSerializer
    queryset = User.objects.filter(entry='Tenant')
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        check = User.objects.filter(entry='Tenant')
        return self.list(check)

class GET_AND_DELETE_userAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.DestroyModelMixin):
    serializer_class =CustomUserSerializer
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    queryset = User.objects.filter(entry='Tenant')
    lookup_field = 'user_id'
    def get(self, request, user_id):
        article = get_object_or_404(User, user_id=user_id)
        serializer = CustomUserSerializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, user_id):
        user = get_object_or_404(User, user_id=user_id)
        # token = Token.objects.get(key='token').user
        # token.delete()
        self.destroy(request)
        return Response('User is successfully deleted', status=status.HTTP_200_OK)


"""An endpoint to GET a specific agent, Update agent info and delete an agent's record"""
class GET_AND_DELETE_AGENT(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request, user_id):
        get_agent = get_object_or_404(User, user_id=user_id)
        serializer = AgentSerializer(get_agent)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, user_id):
        agent = get_object_or_404(User, user_id=user_id)
        token = Token.objects.get_or_create(user=agent)[0].key
        token.delete()
        agent.delete()
        return Response('Agent deleted successfully', status=status.HTTP_204_NO_CONTENT)
 
# OTP is generated for the forget password endpoint
class GenerateOTP(APIView):
    permission_classes = [AllowAny] # Allow everyone to register
    serializer_class = GenrateOTPSerializer # Related pre send verification logic
    def post(self, request):
        code = randint(000000,999999)
        serializer = GenrateOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        check_user = get_object_or_404(User, email=email)
        if check_user.is_verify is False:
            return Response('This user email has not been verified kindly return to the Registration page!',
            status=status.HTTP_401_UNAUTHORIZED)
        # Genrated OTP must be created as an object in the database
        # OTP is unique for every user
        VerifyCode.objects.create(code=code)
        mailjet = Client(auth=(api_key, api_secret), version='v3.1')
        # OTP generated is sent to the User's email and clicking the email will grant the user an access to change-password endpoint
        # There's no special reason for using the generated OTP against the conventional token for the reset-password endpoint
        absurl = f'https://freehouses.herokuapp.com/api/v1/forget_password?OTP={code}&email={email}' 
        email_body = 'Hi '+ ' ' + check_user.name+':\n'+ 'Click on this link to change your password' '\n'+ absurl
        data = {
        'email_body': email_body,'to_email':check_user.email,
        'subject': 'Verify your email'
        }
        data = {
        'Messages': [
            {
            "From": {
                "Email": f"akinolatolulope24@gmail.com",
                "Name": "freehouse"
            },
            "To": [
                {
                "Email": f"{check_user.email}",
                "Name": f"{check_user.name}"
                }
            ],
            "Subject": "Email Verification With OTP",
            "TextPart": "This is your OTP below!",
            "HTMLPart":  email_body
            }
        ]
        }

        result = mailjet.send.create(data=data)
        response = result.json()
        return Response({'message':"OTP sent, check your email"}, status=status.HTTP_200_OK)
      

"""A Custom Password reset view"""
class PasswordReset(APIView):
    permisssion_classes = [AllowAny]
    def put(self, request):
        response = request.GET.get('OTP')
        email = request.GET.get('email')
        try:
            verify_OTP = get_object_or_404(VerifyCode, code=response)
            five_minutes_ago = timedelta(minutes=5)
            t = datetime().time.now()
            current_time = time.strftime("%H:%M:%S", t)
            code_time_check  = current_time - verify_OTP.add_time
            if  code_time_check > five_minutes_ago:
            # The OTP expires after five minutes of created and then deleted from the database
                verify_OTP.delete()
                return Response(' The verification code has expired ', status=status.HTTP_403_FORBIDDEN)
            serializer = CustomPasswordResetSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            password = serializer.validated_data['password']
            password2 = serializer.validated_data['confirm_password']
            if password != password2:
                return Response({'Error': 'Password must match!'}, status=status.HTTP_400_BAD_REQUEST)
            get_user = get_object_or_404(User, email=email)
            if password.lower() == password or password.upper() == password or password.isalnum()\
            or not any(i.isdigit() for i in password):
                raise serializers.ValidationError({
                    'password':'Your Password Is Weak',
                    'Hint': 'Min. 8 characters, 1 letter, 1 number and 1 special character'
                })
            get_user.password = password
            get_user.set_password(password)
            get_user.save()
            return Response(
                'Password change is successful, return to login page', 
                status= status.HTTP_200_OK
                )

        except VerifyCode.DoesNotExist:
            return Response('Invalid OTP or OTP has expired', status=status.HTTP_404_NOT_FOUND)




""" Login Athorization Endpoint With Google Token and saving user's info in COOKIES
"""
@api_view(['POST'])
def validate_authorization_code(request):
    serializer = GetAcessTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    authorization_code = serializer.validated_data['code']
    # google authorization code is encoded which needs to be decoded before access_token 
    # could be generated to retrieve logged-in user's info
    uncoded = unquote(authorization_code)
    if authorization_code  is None:
        return Response({
        "message": "Error occured due to Invalid authorization code"}, 
        status=status.HTTP_204_NO_CONTENT
        )
    data = {
            'code': uncoded ,
            'project_id': project_id,
            'client_id': SOCIAL_AUTH_GOOGLE_KEY,
            'client_secret': SOCIAL_AUTH_GOOGLE_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
    }
    response = requests.post('https://oauth2.googleapis.com/token', data=data)
    if not response.ok:
        return Response({
        'message':'Failed to obtain access token from Google'}, 
        status=status.HTTP_400_BAD_REQUEST
        )
    access_token = response.json()['access_token']
    # retrieve user's info from google
    response = requests.get(
    'https://www.googleapis.com/oauth2/v3/userinfo',
    params={'access_token': access_token}
    )
    if not response.ok:
        raise ValidationError('Failed to obtain user info from Google.')
    result = response.json()
    user_login = User.objects.get(email=result['email'])
    if user_login is None:
        raise AuthenticationError("User with this email doesn't exist, kindly sign up")
    token, created = Token.objects.get_or_create(user=user_login)
    return Response({'Token':token.key}, status= status.HTTP_200_OK)    


"""
N.B: A custom login View where user signs in manually, i.e., without google authentication
 """
@swagger_auto_schema(methods=['post'], request_body=LoginSerializer)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    user = get_object_or_404(User, email=email)
    user.backend = 'django.contrib.auth.backends.ModelBackend'    
    if not user.check_password(password):
        return Response({
        "message": "Incorrect Login credentials"},
        status=status.HTTP_401_UNAUTHORIZED
        )
    if not user.is_verify is True:
        return Response({
        'message': 'Email is not yet verified, kindly do that!'}, 
        status= status.HTTP_400_BAD_REQUEST
        )
    if user.is_active is True:
        token, created = Token.objects.get_or_create(user=user)
        login(request, user)
        return Response({'Token':token.key}, status= status.HTTP_200_OK)    
    return Response({
        "message": "Account not active, kindly register!!"}, 
        status=status.HTTP_404_NOT_FOUND
        )


@api_view(["GET"])
def user_logout(request):
    try:
        request.user.auth_token.delete()
        logout(request)
        return Response({"success": _("Successfully logged out.")},
                    status=status.HTTP_200_OK)
    except (AttributeError, User.DoesNotExist):
        return Response ({"Error": _("User not found, enter a valid token.")},
        status=status.HTTP_404_NOT_FOUND)




"""
Handling the login view with Cookies and JWT decoding
"""
class CookiesLoginView(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, 'secret', algorithms='HS256')
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated')
        user = User.objects.filter(email=payload['user']).first()
        Account = get_object_or_404(User, email=user.email)
        Account.backend = 'django.contrib.auth.backends.ModelBackend'    
        if not Account.is_verify is True:
            return Response({
            'message': 'Email is not yet verified, kindly do that!'}, 
            status= status.HTTP_401_UNAUTHORIZED
            )
        token = Token.objects.get_or_create(user=Account)[0].key
        if Account.is_active:
            login(request, Account)
        return Response('Logged in successfully', status = status.HTTP_200_OK)


"""A JWT LOGOUT VIEW MAINLY FOR HANDLING GOOGLE TOKEN
"""
class LogoutView(APIView):
    def get(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "Logout successfully"
        }
        return response





