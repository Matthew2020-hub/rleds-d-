from django.shortcuts import get_object_or_404
from Authentication.models import User
from .serializers import EditProfileSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from drf_yasg.utils import swagger_auto_schema


# User profile's endpoint
class User_Profile(APIView):

    authentication_classes= [TokenAuthentication]
    def get(self, request, email):

        user = get_object_or_404(User, email=email)
        email = user.email
        full_name = user.name
        phone_number = str(user.phone_number)
        profile_image = user.profile_image
        background_image = user.background_image
        entry_type = user.entry
        if not background_image and not profile_image:
            background_image = "https://www.rocketmortgage.com/resources-cmsassets/RocketMortgage.com/Article_Images/Large_Images/TypesOfHomes/types-of-homes-hero.jpg"
            profile_image = "https://www.rocketmortgage.com/resources-cmsassets/RocketMortgage.com/Article_Images/Large_Images/TypesOfHomes/types-of-homes-hero.jpg"
        context = {
            "email": email,
            "full_name": full_name,
            "phone_number": phone_number,
            "entry": entry_type,
            "background_image": background_image,
            "profile_image": profile_image,
        }
        return Response(context, status=status.HTTP_200_OK)
        # ///

    @swagger_auto_schema(request_body=EditProfileSerializer)
    def put(self, request): 

        serializer = EditProfileSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        get_user = get_object_or_404(User,email=email)
        get_user.update(**request.data)
        context = {
            "message": "Profile Update is sucessful",
            "data": serializer.data,
        }
        return Response(context, status=status.HTTP_200_OK)
