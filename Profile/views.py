from distutils.log import error
from django.shortcuts import render
from django.contrib.auth.decorators import login_required 
from Authentication.models import User
from .serializers import ProfileSerializer
from .models import Profile
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
# Create your views here.
@api_view(['GET'])
@permission_classes([AllowAny])
def profile(request):
    try:
        email = request.user.email
        name = request.user.name
        context = {
            'email': email,
            'full_name': name
        }
        return Response(context,status=status.HTTP_200_OK)
    except Exception as e:
        return Response('User does not exist!', status=status.HTTP_204_NO_CONTENT)