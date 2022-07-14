
from .serializers import (
    ApartmentSearchSerializer, ApartmentSerializer, 
    ApartmentReviewSerializer, ReturnApartmentInfoSerializer
)
from .models import Apartment
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from .pagination import CustomPagination
from Authentication.models import User


"""An endpoint to post or create an apartment"""
class ApartmentCreateAPIView(generics.GenericAPIView, mixins.CreateModelMixin):
    serializer_class = ApartmentSerializer
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]

    def post(self, request):
     
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
       
        agent_name = serializer.validated_data['agent']
        # serializer.save()
        try:
            # verify that the person creating an apartment is an agent
            verify_user= User.objects.get(name=agent_name)
            if verify_user.entry != "Agent":
                return Response ("Only an agent can post an apartment", status=status.HTTP_401_UNAUTHORIZED)
            apartment = Apartment.objects.create(**validated_data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
               
        except User.DoesNotExist: 
            return Response("Agent with this name does not exist", status=status.HTTP_404_NOT_FOUND)
       




"""An endpoint to list all available apartments"""

class ApartmentListAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = ReturnApartmentInfoSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'apartment_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        if not self.get_queryset():
            return Response("No apartment is available", status=status.HTTP_204_NO_CONTENT)
        return Response(
            self.serializer_class(self.get_queryset(), many=True).data, 
            status=status.HTTP_200_OK
            )




"""An endpoint to get, delete and update a particular endpoint"""
class ApartmentCreateUpdateDestroyAPIView(
    generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin, 
    mixins.DestroyModelMixin
    ):
    serializer_class = ApartmentSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'apartment_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request, apartment_id):
        apartment = get_object_or_404(Apartment, apartment_id=apartment_id )
        serializer = ApartmentSerializer(apartment)
        review = ApartmentReviewSerializer(apartment)
        context = {
            "apartment details": serializer.data,
            "review": review.data
        }
        return Response(context, status=status.HTTP_200_OK)

    def put(self, request, apartment_id):
        apartment = get_object_or_404(Apartment, apartment_id=apartment_id)   
        serializer = self.serializer_class(apartment, data=request.data)   
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response('Data update was successful', status=status.HTTP_200_OK)

    def delete(self, request, apartment_id):
        get_apartment = get_object_or_404(Apartment, apartment_id=apartment_id)
        self.destroy(get_apartment)
        return Response('Apartment deleted successfully', status=status.HTTP_204_NO_CONTENT)



""" An endpoint to list the apartment search result
"""
class ApartmentSearchListAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = ApartmentSearchSerializer
    lookup_field = 'location'
    pagination_class = CustomPagination
    queryset = Apartment.objects.all()
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]


    def post(self, request):
        serializer = ApartmentSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data['location']
        price = serializer.validated_data['price']
        category = serializer.validated_data['category']
        apartments = Apartment.objects.filter(
            location=location, price=price, 
            category=category
            )
        return self.list(apartments, many=True)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def apartment_reviews_create(request, apartment_id):
    serializer = ApartmentReviewSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    review = serializer.validated_data['reviews']
    try:
        apartment = Apartment.objects.get(apartment_id=apartment_id)
        if apartment:
            apartment.reviews = review
            apartment.save()
            return Response("review submitted", status=status.HTTP_200_OK)
    except Apartment.DoesNotExist:
        return Response("Apartment with ID does not exist", status=status.HTTP_404_NOT_FOUND)
