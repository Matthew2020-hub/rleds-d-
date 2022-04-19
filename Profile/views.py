from django.shortcuts import get_object_or_404
from Authentication.models import User
from .serializers import EditProfileSerializer, ProfileSerializer
from .models import Profile
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes, authentication_classes

# User profile's endpoint
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def profile(request, email):
    serializer = EditProfileSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    name = serializer.validated_data['First_name']
    user_email = serializer.validated_data['Email']
    profile_image = serializer.validated_data['Profile_image']
    background_image = serializer.validated_data['Background_image']
    location = serializer.validated_data['Location']
    get_user = User.objects.filter(email=email).update(name=name, profile_image=profile_image,background_image=background_image, email=user_email, agent_location=location)
    if get_user:
        return Response('Profile Update is sucessful', status=status.HTTP_200_OK)











    # if request.method == 'GET':
    #     try:
    #         get_user = Token.objects.get(key=request.auth.key).user
    #         user = get_object_or_404(User, name=get_user.name)
    #         email = user.email
    #         full_name = user.name
    #         context = {
    #             'email': email,
    #             'full_name': full_name
    #         }
    #         return Response(context,status=status.HTTP_200_OK)
    #     except User.DoesNotExist:
    #         return Response('User does not exist!', status=status.HTTP_204_NO_CONTENT)
     
