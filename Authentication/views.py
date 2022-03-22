from audioop import reverse
from lib2to3.pgen2.tokenize import TokenError
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
CustomUserSerializer)
from .models import User, VerifyCode
from message.models import Room
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
from rest_framework import generics
from rest_auth.views import LoginView as RestLoginView
from django.contrib.auth import logout, login
from django.utils.translation import gettext_lazy as _
from dev.settings import SOCIAL_AUTH_GOOGLE_KEY, SOCIAL_AUTH_GOOGLE_SECRET, redirect_uri, project_id
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

env = environ.Env()
environ.Env.read_env('housefree.env')
from_email= os.environ.get('EMAIL_HOST_USER')

api_key = os.environ.get('MJ_API_KEY')
api_secret = os.environ.get('MJ_API_SECRET')      


TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_NUMBER = os.environ.get("TWILIO_NUMBER")




class GenerateOTP(APIView):
    permission_classes = [IsAuthenticated] # Allow everyone to register
    serializer_class = VerifyCodeSerializer # Related pre send verification logic
    def generate_code(self):
        # generate a random OTP
        otp = randint(000000,999999)
        return otp
    def post(self, request, email):
        code = self.generate_code()
        user = get_object_or_404(User, email=email)
        if user.is_verify is False:
            return Response('This user email has not been verified kindly return to the Registration page!', status=status.HTTP_401_UNAUTHORIZED)
        # Genrated OTP must be created as an object in the database
        VerifyCode.objects.create(code=code)
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
            "TextPart": "This is your OTP below!",
            "HTMLPart":  f"This is your OTP: {code}"
            }
        ]
        }
        result = mailjet.send.create(data=data)
        return Response("OTP sent, check your phone", status=status.HTTP_200_OK)


@permission_classes(AllowAny)
@api_view(['GET'])
def validate_OTP(self, code):
    verify_records = get_object_or_404(VerifyCode, code=code)
    if verify_records:
        five_minutes_ago = datetime.now(ZoneInfo("America/Los_Angeles")) + timedelta(minutes=5)
        if verify_records.add_time > five_minutes_ago:
            # The OTP expires after five minutes of created and then deleted from the database
            verify_records.delete()
            return Response(' The verification code has expired ', status=status.HTTP_403_FORBIDDEN)
        # To keep the database safe, the OTP is deleted after validation
        verify_records.delete()
        return Response("OTP code is valid", status=status.HTTP_200_OK)


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
class Registration(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['password']
        try:
            validators.validate_password(password)
            user = serializer.save()
            user_token = Token.objects.create(user=user)
            context = {
                'token': user_token.key,
                'message': 'Check your email and verify',
                "data": serializer.data
        }
            return Response(context, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def refreshToken( request, email):
    get_token = get_object_or_404(User, email = email)
    if get_token.is_verify is True:
        return Response('User already verified', status=status.HTTP_208_ALREADY_REPORTED)
    email_verification_token = RefreshToken.for_user(get_token).access_token
    current_site = get_current_site(request).domain
    absurl = f'https://freehouses.herokuapp.com/api/v1/email-verify?token={email_verification_token}' 
    email_body = 'Hi'+ ''+ get_token.name+':\n'+ 'Use link below to verify your email' '\n'+ absurl
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
    # print(result.status_code)
    return Response(result.json(), 
        status=status.HTTP_201_CREATED)
    # send_mail(
    # subject = 'verify email',
    # message = email_body,
    # from_email= from_email,
    # recipient_list= [get_token.email],
    # fail_silently=False
    # )
    # return Response('Check your email for verification', status=status.HTTP_200_OK)

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
class GET_AND_DELETE_USER(APIView):
    serializer_class =CustomUserSerializer
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request, user_id):
        article = get_object_or_404(User, user_id=user_id)
        serializer = CustomUserSerializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, user_id):
        user = get_object_or_404(User, user_id=user_id)
        user.delete()
        return Response('User is successfully deleted', status=status.HTTP_200_OK)

"""A Custom Password reset view"""
class PasswordReset(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def put(self, request, user_id):
        serializer = CustomPasswordResetSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        get_user = get_object_or_404(User, email=email, user_id=user_id)
        if password.lower() == password or password.upper() == password or password.isalnum()\
        or not any(i.isdigit() for i in password):
            raise serializers.ValidationError({
                'password':'your password is weak',
                'Hint': 'It must be alphanumeric, must contain an Upper and Lower case character and it must be a minimum of 8 characters long '
            })
        get_user.password = password
        get_user.set_password(password)
        get_user.save()
        return Response(
            'Password change is successful, return to login page', 
            status= status.HTTP_200_OK
            )

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
        status=status.HTTP_404_NOT_FOUND
        )
    if not user.is_verify is True:
        return Response({
        'message': 'Email is not yet verified, kindly do that!'}, 
        status= status.HTTP_400_BAD_REQUEST
        )
    if user.is_active is True:
        try:
            token, created = Token.objects.get_or_create(user=user)
            login(request, user)
            return Response({'token':token.key}, status= status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response('Token matching query does not exist', status=status.HTTP_404_NOT_FOUND)
        
    return Response({
        "message": "Account not active, kindly register!!"}, 
        status=status.HTTP_403_FORBIDDEN
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



"""Agent's Login Athorization Endpoint With Google Token and saving user's info in COOKIES
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
    payload = {
          "user": user_login.email,
           "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            "iat": datetime.datetime.utcnow()
                }
    # user's info is been saved in a jwt-cookie to prevent logout user unnecessarily
    token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')
    response = Response()
    response.set_cookie(key='jwt', value=token, httponly=True)
    return Response(result, status=status.HTTP_200_OK)


"""
Handling the login view with Cookies and JWT decoding
"""
class CookiesLoginView(APIView):
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
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "Logout successfully"
        }
        return response


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
        agent.delete()
        return Response('Agent deleted successfully', status=status.HTTP_200_OK)


