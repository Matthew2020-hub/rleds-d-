from uritemplate import partial
from .serializers import (
    ApartmentSearchSerializer,
    ApartmentSerializer,
    ApartmentReviewSerializer,
    ReturnApartmentInfoSerializer,
)
from .models import Apartment
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from drf_yasg.utils import swagger_auto_schema
from Authentication.models import User
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie
from django.db import IntegrityError
from rest_framework.exceptions import APIException


class ApartmentCreate(APIView):

    """An endpoint to post or create an apartment"""

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]

    @swagger_auto_schema(request_body=ApartmentSerializer)
    def post(self, request):
        try:
            serializer = ApartmentSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data
            agent_name = serializer.validated_data["agent"]
            # serializer.save()
            try:
                # verify that the person creating an apartment is an agent
                verify_user = User.objects.get(name=agent_name)
                if verify_user.entry != "Agent":
                    return Response(
                        "Only an agent can post an apartment",
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
                apartment = Apartment.objects.create(**validated_data)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

            except User.DoesNotExist:
                return Response(
                    "Agent with this name does not exist",
                    status=status.HTTP_404_NOT_FOUND,
                )
        except IntegrityError as exec:
            raise APIException(detail=exec)


class ApartmentList(APIView):
    """An endpoint to list all available apartments"""

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    @method_decorator(vary_on_cookie)
    @method_decorator(cache_page(60*60*12))
    def get(self, request):
        queryset = Apartment.objects.all()
        if not queryset:
            return Response(
                "No apartment is available", 
                status=status.HTTP_204_NO_CONTENT
            )
        apartment_list = ReturnApartmentInfoSerializer(queryset, many=True)
        return Response(
            apartment_list.data,
            status=status.HTTP_200_OK,
        )


class ApartmentListUpdateDelete(APIView):

    """
    An endpoint to get, delete and update a particular endpoint
    Args:
        Apartment ID- a unique ID to fetch apartment data
    Response:
        HTTP_200-OK- a success response and apartment data
        HTTP_204_NO_CONTENT- if apartment has been deleted
    Raise:
        HTTP_404_NOT_FOUND- if apartment with ID does not exist
    """

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request, apartment_id):
        apartment = get_object_or_404(Apartment, apartment_id=apartment_id)
        serializer = ApartmentSerializer(apartment)
        review = ApartmentReviewSerializer(apartment)
        context = {
            "apartment details": serializer.data, 
            "review": review.data
            }
        return Response(context, status=status.HTTP_200_OK)

    @swagger_auto_schema(request_body=ApartmentSerializer)
    def put(self, request, apartment_id):
        try:
            apartment = Apartment.objects.filter(apartment_id=apartment_id)
            serializer = ApartmentSerializer(
                apartment, 
                data=request.data, 
                partial=True
                )
            serializer.is_valid(raise_exception=True)
            apartment.update(**serializer.validated_data)
            return Response(
                "Data update was successful", status=status.HTTP_200_OK
            )
        except Apartment.DoesNotExist:
            return Response(
                "Apartment with ID does not exist!", 
                status=status.HTTP_404_NOT_FOUND
                )


    def delete(self, request, apartment_id):
        get_apartment = get_object_or_404(
            Apartment, apartment_id=apartment_id
            )
        get_apartment.delete()
        return Response(
            "Apartment deleted successfully", 
            status=status.HTTP_204_NO_CONTENT
        )


class ApartmentSearch(APIView):

    """
    An endpoint to list the apartment search result
    Args:
        data- serializer search data(location, price, category)
    Response:
        HTTP_200_OK- if apartment(s) matching search query exists
    Raise:
        HTTP_404_NOT_FOUND- if search query does not exist
    """
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=ApartmentSearchSerializer)
    def post(self, request):
        serializer = ApartmentSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data["location"]
        price = serializer.validated_data["price"]
        category = serializer.validated_data["category"]
        apartments = Apartment.objects.filter(
            location=location, price=price, category=category
        )
        if apartments is None:
            return Response(
                "Search result not found", status=status.HTTP_404_NOT_FOUND
            )
        apartment_details = ReturnApartmentInfoSerializer(
            apartments, many=True
        )
        return Response(apartment_details, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@swagger_auto_schema(request_body=ApartmentReviewSerializer)
def apartment_reviews_create(request, apartment_id):
    serializer = ApartmentReviewSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    review = serializer.validated_data["reviews"]
    apartment = get_object_or_404(Apartment, apartment_id=apartment_id)
    apartment.reviews = review
    apartment.save()
    return Response("review submitted", status=status.HTTP_200_OK)
