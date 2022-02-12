from unicodedata import category
from django.shortcuts import render

# Create your views here.
from django.http.response import JsonResponse
from django.shortcuts import render
from .serializers import ApartmentSearchSerializer, ApartmentSerializer
from .models import Apartment
from django.shortcuts import get_object_or_404
# Create your views here.
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import BasicAuthentication, SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view
import requests
from .pagination import CustomPagination


class CreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
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

class CreateUpdateDestroyAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin):
    serializer_class = ApartmentSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'apartment_id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request, apartment_id):

        queryset = Apartment.objects.filter(apartment_id = apartment_id)
        article = get_object_or_404(queryset)
        serializer = ApartmentSerializer(article)
        return Response(serializer.data)

    def put(self, request, apartment_id):
        query = Apartment.objects.filter(apartment_id=apartment_id)
        if query:
            return self.update(request)
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request, apartment_id):
        query = Apartment.objects.get(apartment_id=apartment_id)
        if query:
            return self.destroy(request)


class ListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = ApartmentSerializer
    lookup_field = 'location'
    pagination_class = CustomPagination
    queryset = Apartment.objects.all()
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        serializer = ApartmentSearchSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            location = serializer.validated_data['location']
            price_range = serializer.validated_data['price_range']
            category = serializer.validated_data['category']
            query = Apartment.objects.filter(location=location, price=price_range, category=category)
            if query is not None:
                return self.list(query)
