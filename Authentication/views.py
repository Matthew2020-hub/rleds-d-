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
CustomPasswordResetSerializer, AgentSerializer, 
CustomUserSerializer)
from .models import User
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
from rest_framework.decorators import api_view, permission_classes
from rest_framework import generics
from rest_auth.views import LoginView as RestLoginView
from django.contrib.auth import logout, login
from django.utils.translation import gettext_lazy as _
from dev.settings import SOCIAL_AUTH_GOOGLE_KEY, SOCIAL_AUTH_GOOGLE_SECRET, redirect_uri, project_id
from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import redirect
from django.shortcuts import redirect, render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
import requests
from rest_framework.exceptions import AuthenticationFailed
import jwt, datetime
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .utils import Util
from django.conf import settings
from django.core.mail import send_mail
from django.utils.http import unquote
from django.contrib.auth import authenticate
from django.contrib import messages
from drf_yasg.utils import swagger_auto_schema
import os
import environ
from transaction.models import Rooms

env = environ.Env()
environ.Env.read_env('housefree.env')
from_email= os.environ.get('EMAIL_HOST_USER')

"""An endpoint to create user and to GET list of all users"""
class CreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = CustomUserSerializer
    queryset = User.objects.filter(entry='Tenant')
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        print(request.user)
        check = User.objects.filter(entry='Tenant')
        return self.list(check)
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = serializer.save()
        get_token = User.objects.get(email = user_data['email'])
        token = RefreshToken.for_user(get_token).access_token
        current_site = get_current_site(request).domain
        absurl = f'http://127.0.0.1:8000/api/v1/email-verify?token={token}' 
        email_body = 'Hi'+ ''+ get_token.name+':\n'+ 'Use link below to verify your email' '\n'+ absurl
        data = {
            'email_body': email_body,'to_email':get_token.email,
            'subject': 'Verify your email'
        }
        send_mail(
        subject = 'verify email',
        message = email_body,
        from_email= from_email,
        recipient_list= [get_token.email],
        fail_silently=False
        )
        return Response(user_data, status=status.HTTP_201_CREATED)

"""Verify user email endpoint"""
class VerifyEmail(generics.GenericAPIView):
    serializer_class = CustomUserSerializer
    queryset = User.objects.all()
    lookup_field = 'email'
    permisssion_classes = [AllowAny]
    def get(self, request):
        serializer = CustomUserSerializer
        token = request.GET.get('token')
        access_token_str = str(token)
        print(request.user)
        try:
            access_token_obj = AccessToken(access_token_str)
        except Exception as e:
            return Response(
        'Token already expired', 
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
class CreateUpdateDestroyAPIView(
    generics.GenericAPIView, mixins.ListModelMixin, 
    mixins.UpdateModelMixin, mixins.DestroyModelMixin
    ):
    serializer_class =CustomUserSerializer
    queryset =User.objects.filter(entry='Tenant')
    lookup_field = 'user_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request, user_id):
        queryset = User.objects.filter(user_id = user_id)
        article = get_object_or_404(queryset)
        serializer = CustomUserSerializer(article)
        return Response(serializer.data)

    def delete(self, request, user_id):
        query = User.objects.get(user_id=user_id)
        if query is not None:
            return self.destroy(request)
        return Response('Invalid user ID', status= status.HTTP_404_NOT_FOUND)

"""A Custom Password reset view"""
class PasswordResetAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin):
    serializer_class = CustomPasswordResetSerializer
    queryset = User.objects.all()
    lookup_field = 'user_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def put(self, request, user_id):
        serializer = CustomPasswordResetSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        phone_number = serializer.validated_data['phone_number']
        password = serializer.validated_data['password']
        get_user = get_object_or_404(User, email=email, phone_number=phone_number)
        for user in get_user:
            user.password = password
            user.set_password(password)
            user.save()
            return Response(
                'Password change is successful, return to login page', 
                status= status.HTTP_200_OK
                )
"""
To prevent logging out a user unnecessarily, user's data retrieved from google
 is being saved in JWT with an expiration time
"""
class SetLoginView(APIView):
        def post(self, request):
            try:
                serializer = LoginSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                email = serializer.validated_data['email']
                password = serializer.validated_data['password']
                query = User.objects.filter(entry='Tenant')
                queryset = query.objects.get(email=email)
                if not queryset.check_password(password):
                    raise AuthenticationFailed("Incorrect Password")
                payload = {
                    "user": queryset.email,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                    "iat": datetime.datetime.utcnow()
                }
                token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')
                response = Response()
                response.set_cookie(key='jwt', value=token, httponly=True)
                response.data = {
                    'jwt': token
                }           
                return Response(response, status= status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({
                "error": _("User with this email does not exist!")}, 
                status=status.HTTP_404_NOT_FOUND
                )


"""
N.B: A custom login View where user signs in manually, i.e., without google authentication
 """
@swagger_auto_schema(methods=['post'], request_body=LoginSerializer)
@api_view(["POST"])
@permission_classes([AllowAny])
def login(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    Account = get_object_or_404(User, email=email)
    Account.backend = 'django.contrib.auth.backends.ModelBackend'    
    if not Account.check_password(password):
        return Response({
        "message": "Incorrect Login credentials"},
        status=status.HTTP_401_UNAUTHORIZED
        )
    if not Account.is_verify is True:
        return Response({
        'message': 'Email is not yet verified, kindly do that!'}, 
        status= status.HTTP_401_UNAUTHORIZED
        )
    token = Token.objects.get_or_create(user=Account)[0].key
    if Account and Account.is_active is True:
        return Response({'token':token}, status= status.HTTP_200_OK)
    else:
        return Response({
        "message": "Account not active, kindly register!!"}, 
        status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(["GET"])
def logout(request):
    print(request.user)
    try:
        request.user.auth_token.delete()
        logout(request)
        return Response({"success": _("Successfully logged out.")},
                    status=status.HTTP_200_OK)
    except (AttributeError, User.DoesNotExist):
        return Response ({"Error": _("User not found, enter a valid token.")},
        status=status.HTTP_404_NOT_FOUND)



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

"""Agent's Login Athorization Endpoint With Google Token and saving user's info in COOKIES
"""
@api_view(['POST'])
def validate_authorization_code(request):
    serializer = GetAcessTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    authorization_code = serializer.validated_data['code']
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
    response = requests.get(
    'https://www.googleapis.com/oauth2/v3/userinfo',
    params={'access_token': access_token}
    )
    if not response.ok:
        raise ValidationError('Failed to obtain user info from Google.')
    result = response.json()
    login = User.objects.get(email=result['email'])
    if login is None:
        raise AuthenticationError("User with this email doesn't exist, kindly sign up")
    payload = {
          "user": login.email,
           "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            "iat": datetime.datetime.utcnow()
                }
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

"""Delete JWT TOKEN WITH LOGOUT VIEW"""
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "Logout successfully"
        }
        return response


"""An endpoint to create user and to GET list of all users"""
class AgentCreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = AgentSerializer
    queryset = User.objects.filter(entry='Agent')
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        check = User.objects.filter(entry='Agent')
        return self.list(check)
    def post(self, request):
        serializer = AgentSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = self.create(request)
        get_token = User.objects.get(email = user_data['email'])
        token = RefreshToken.for_user(get_token).access_token
        current_site = get_current_site(request).domain
        absurl = f'http://127.0.0.1:8000/api/v1/email-verify?token={token}' 
        email_body = 'Hi'+''+get_token.name+':\n'+ 'Use link below to verify your email' '\n'+ absurl
        data = {
            'email_body': email_body,
            'to_email':get_token.email,
            'subject': 'Verify your email'
        }
        send_mail(
        subject = 'verify email',
        message = email_body,
        from_email= from_email,
        recipient_list=[get_token.email],
        fail_silently=False
        )
        return Response(user_data, status=status.HTTP_201_CREATED)

"""An endpoint to GET a specific agent, Update agent info and delete an agent's record"""
class AgentCreateUpdateDestroyAPIView(
    generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin, 
    mixins.DestroyModelMixin
    ):
    serializer_class = AgentSerializer
    queryset = User.objects.filter(entry='Agent')
    lookup_field = 'user_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request, user_id):
        get_agent = get_object_or_404(User, user_id=user_id)
        serializer = AgentSerializer(get_agent)
        return Response(serializer.data)

    def delete(self, request, user_id):
        query = get_object_or_404(User, user_id=user_id)
        if query:
            return self.destroy(request)


