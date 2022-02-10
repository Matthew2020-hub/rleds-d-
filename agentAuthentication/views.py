from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.urls import reverse_lazy
# Create your views here.
from http.client import responses
from multiprocessing import AuthenticationError
from lib2to3.pgen2 import token
from os import access
import re
from django.forms import ValidationError
from django.http import request, response
from django.http.response import JsonResponse
from django.shortcuts import render
from .serializers import (AgentSerializer,AgentLoginSerializer, GetAcessTokenSerializer,
CustomPasswordResetSerializer, SocialSerializer)
from userAuthentication.models import User
from django.shortcuts import get_object_or_404
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
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
from urllib.parse import unquote
import urllib.parse

"""An endpoint to crreate user and to GET list of all users"""
class CreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = AgentSerializer
    queryset = User.objects.filter(entry='Agent')
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        check = User.objects.filter(entry='Agent')
        return self.list(check)
    def post(self, request):
        return self.create(request)

"""An endpoint to GET a specific user, Update user info and delete a user's record"""
class CreateUpdateDestroyAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin):
    serializer_class = AgentSerializer
    queryset = User.objects.filter(entry='Agent')
    lookup_field = 'user_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request, user_id):
        queryset = User.objects.filter(user_id = user_id)
        article = get_object_or_404(queryset)
        serializer = AgentSerializer(article)
        return Response(serializer.data)
    def put(self, request, user_id):
        query = User.objects.filter(user_id=user_id)
        if query:
            return self.update(request)
        return Response(status=status.HTTP_401_UNAUTHORIZED)
    def delete(self, request, user_id):
        query = User.objects.get(apartment_id=user_id)
        if query:
            return self.destroy(request)

"""A Custom Password reset view"""
class CreateUpdateAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin):
    serializer_class = CustomPasswordResetSerializer
    queryset = User.objects.filter(entry='Agent')
    lookup_field = 'user_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def put(self, request, user_id):
        serializer = CustomPasswordResetSerializer(data= request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            phone_number = serializer.validated_data['phone_number']
            password = serializer.validated_data['password']
            print(password)
            queryset = User.objects.filter(entry='Agent')
            query = queryset.filter(email=email, phone_number=phone_number)
            if query:
                print(password)
                return self.update(request)
            return Response(status=status.HTTP_401_UNAUTHORIZED)
"""
Handling Agent's Login with Google session with JWT and setting cookies
"""
class SetLoginView(APIView):
        def post(self, request):
            try:
                serializer = AgentLoginSerializer(data=request.data)
                if serializer.is_valid(raise_exception=True):
                    email = serializer.validated_data['email']
                    password = serializer.validated_data['password']
                    queryset = AgentLoginSerializer.objects.get(email=email)
                    if not queryset.check_password(password):
                        raise AuthenticationFailed("Incorrect Password")
                    elif queryset is None:
                        pass
                #         raise AuthenticationFailed("User not found")
                #     payload = {
                #         "user": queryset.email,
                #         "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                #         "iat": datetime.datetime.utcnow()
                #     }
                #     token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')
                #     response = Response()
                #     response.set_cookie(key='jwt', value=token, httponly=True)
                #     response.data = {
                #         'jwt': token
                #     }           
                # return response
            except User.DoesNotExist:
                return Response({"error": _("User with this email does not exist!")}, status=status.HTTP_404_NOT_FOUND)
"""
Handling the login view with Cookies and JWT decoding
"""
class CookiesLoginView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            pass
        #     raise AuthenticationFailed('Unauthenticated')
        # try:
        #     payload = jwt.decode(token, 'secret', algorithms='HS256')
        # except jwt.ExpiredSignatureError:
        #     raise AuthenticationFailed('Unauthenticated')
        # user = User.objects.filter(email=payload['user']).first()
        # serializer = User(user)
        return Response(serializer.data, status = status.HTTP_200_OK)

@api_view(['POST'])
def validate_authorization_code(request):
    serializer = GetAcessTokenSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        code = serializer.validated_data['code']
        uncoded = unquote(code)
        if code  is None:
            return Response({"message": "Error occured due to Invalid authorization code"}, status=status.HTTP_204_NO_CONTENT)
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
            return Response({'message':'Failed to obtain access token from Google'}, status=status.HTTP_400_BAD_REQUEST)
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
    return Response(result, status=status.HTTP_200_OK)



"""A manaual or Custom login and logout View without cookies.
N.B: This is login view when user signs in manually, i.e., without google authentication
 """
class Login(RestLoginView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    serializer_class = AgentLoginSerializer
    def post(self, request, *args, **kwargs):
        try:
            serializer = AgentLoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data['email']
                password = serializer.validated_data['password']
                queryset = User.objects.get(email=email)
                if not queryset.check_password(password):
                    raise AuthenticationFailed("Incorrect Password")
                elif queryset is None: 
                    raise AuthenticationFailed("User not found")        
                return Response( status=status.HTTP_200_OK)  
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": _("User with this email does not exist!")}, status=status.HTTP_404_NOT_FOUND)

@api_view(["GET"])
def logout(request):
    try:
        request.user.auth_token.delete()
        logout(request)
        return Response({"success": _("Successfully logged out.")},
                    status=status.HTTP_200_OK)
    except (AttributeError, User.DoesNotExist):
        return Response ({"Error": _("User not found, enter a valid token.")},
        status=status.HTTP_404_NOT_FOUND)
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "Logout successfully"
        }
        return response