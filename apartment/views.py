
from django.shortcuts import render
from .serializers import ApartmentSearchSerializer, ApartmentSerializer
from .models import Apartment, Media
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
    # authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]

    def post(self, request):
        # makes the request data mutable so to make pop url possible
        # request.data._mutable=True
        apartment_data = request.data
        # To store an array of image url, a new table (media) was created, because media has a separate table
        # Apartment model serializer would throw an error when url is being passed to it from frontend, 
        # that's why the media url is being popped out and saved in a separate variable
        media_url = apartment_data.pop("image_url") or None
        # request.data._mutable=False
        if media_url is None:
            return Response("media url can not be None", status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(data=apartment_data)
        serializer.is_valid(raise_exception=True)
        agent_name = serializer.validated_data['agent']
        try:
            # verify that the person creating an apartment is an agent
            verify_user= User.objects.get(name=agent_name)
            if verify_user.entry != "Agent":
                return Response ("Only an agent can post an apartment", status=status.HTTP_401_UNAUTHORIZED)
            instance = serializer.save()
            for url in media_url:
                
                media, created = Media.objects.get_or_create(image_url=url)
                media.apartment.add(instance)
                return Response("apartment created successfully", status=status.HTTP_201_CREATED)
               
        except User.DoesNotExist: 
            return Response("Agent with this name does not exist", status=status.HTTP_404_NOT_FOUND)
       




"""An endpoint to list all available apartments"""

class ApartmentListAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = ApartmentSerializer
    queryset = Apartment.objects.all()
    lookup_field = 'id'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        list_all_apartment = Apartment.objects.all()
        for apartment in list_all_apartment:
            media = Media.objects.filter(apartment=apartment)
            for medium in media:
                print(medium.image_url)
                context = {
                    "apartment": apartment,
                    "image_url": medium.image_url
                }
                return self.list(context)


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
        media = Media.objects.filter(apartment=article)
        images = []
        for image in media:
            images.append(image.image_url)
        serializer = ApartmentSerializer(article)
        context = {
            "data": serializer.data,
            "image": images
        }
        return Response(context, status=status.HTTP_200_OK)

    def put(self, request, apartment_id):
        query = get_object_or_404(Apartment, apartment_id=apartment_id)
        request.data._mutable = True
        get_media_url = request.data
        # Checking if there's an image url in the request data
        verify_apartment_image = get_media_url.pop('url') or None
        request.data._mutable = False
        if verify_apartment_image is None: 
            #Update Apartment table if reqest data to be updated  doesn't contain any image   
            serializer = ApartmentSerializer(query, data=request.data)   
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response('Data update was successful', status=status.HTTP_200_OK)
        # Update Media table alongside Apartment if request data has an image(s) url
        get_media_object = Media.objects.get(apartment=query)
        get_media_object.url = verify_apartment_image
        serializer = ApartmentSerializer(query, data=get_media_url)   
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response('Data update was successful', status=status.HTTP_200_OK)
        

    def delete(self, request, apartment_id):
        get_apartment = get_object_or_404(Apartment, apartment_id=apartment_id)
        get_image = get_object_or_404(Media, apartment=get_apartment)
        self.destroy(get_apartment, get_image)
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


    # def get(self, request):
    #     list_apartment = Apartment.objects.all()
    #     return self.list(list_apartment)
    def post(self, request):
        serializer = ApartmentSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        location = serializer.validated_data['location']
        price = serializer.validated_data['price']
        category = serializer.validated_data['category']
        apartment = Apartment.objects.filter(
            location=location, price=price, 
            category=category
            )
        apartment_list = []
        for apartments in apartment:
            # media_url = Media.objects.get(apartment=apartments)
            if apartments.is_available is True:
                apartment_list.append([{
                   "apartment title": apartments.aparment_title,
                   "category": apartments.category,
                #    "videofile": apartments.videofile,
                   "location": apartments.location,
                   "agent": apartments.agent,
                   "features": apartments.feautures,
                   "location info": apartments.location_info,
                   "reviews": apartments.reviews,
                #    "images": media_url.image_url

                }])
                context = {
                    "data": apartment_list
                }
                return Response(apartment_list, status=status.HTTP_200_OK
                )
        return Response('No result found', status=status.HTTP_204_NO_CONTENT)
