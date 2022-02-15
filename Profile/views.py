from django.shortcuts import render
from django.contrib.auth.decorators import login_required 
from Authentication.models import User
from .serializers import ProfileSerializer
from .models import Profile
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
# Create your views here.
@api_view(['GET'])
def profile(request):
    email = request.user.email
    name = request.user.name
    context = {
        'email': email,
        'full_name': name
    }
    return Response(context,status=status.HTTP_200_OK)