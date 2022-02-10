from django.shortcuts import render

# Create your views here.
from django.shortcuts import render

# Create your views here.

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.core.mail import send_mail

from .serializers import ContactUsSerailizer

@api_view(['POST','GET'])
def contact_us(request):
    # queryset = ContactUs.objects.all()
    serializer = ContactUsSerailizer(data=request.data)
    if serializer.is_valid(raise_exception = True):
        sender = serializer.validated_data['sender']
        message = serializer.validated_data['message']

            # send mail
        send_mail(
            subject = 'Contact Form mail ' ,
            message = message,
            from_email= sender,
            recipient_list=
            ['housefree189@gmail.com'],
            fail_silently=False
        )
        # serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)