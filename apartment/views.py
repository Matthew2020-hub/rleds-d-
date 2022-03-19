import requests
from unicodedata import category
from django.shortcuts import render
from django.shortcuts import render
from .serializers import ApartmentSearchSerializer, ApartmentSerializer
from .models import Apartment
from django.shortcuts import get_object_or_404
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view
from .pagination import CustomPagination

"""An endpoint to post and to list all available apartment"""
class ApartmentCreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = ApartmentSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request):
        check = Apartment.objects.all()
        return self.list(check)

    def post(self, request):
        return self.create(request)


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
        article = get_object_or_404(Apartment, apartment_id=apartment_id )
        serializer = ApartmentSerializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, apartment_id):
        query = get_object_or_404(Apartment, apartment_id=apartment_id)
        serializer = ApartmentSerializer(query, data=request.data)   
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response('Data update was successful', status=status.HTTP_200_OK)

    def delete(self, request, apartment_id):
        query = get_object_or_404(Apartment, apartment_id=apartment_id)
        self.destroy(query)
        return Response('Apartment deleted successfully', status=status.HTTP_204_NO_CONTENT)

""" An endpoint to list the apartment search result
"""
class ApartmentListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = ApartmentSearchSerializer
    lookup_field = 'location'
    pagination_class = CustomPagination
    queryset = Apartment.objects.all()
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        serializer = ApartmentSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data['location']
        price_range = serializer.validated_data['price_range']
        category = serializer.validated_data['category']
        apartment = get_object_or_404(
             Apartment, location=location, price=price_range, 
            category=category
            )
        if apartment.is_available is True:
            return self.list(apartment, status=status.HTTP_200_OK
            )
        return Response('No result found', status=status.HTTP_204_NO_CONTENT)
