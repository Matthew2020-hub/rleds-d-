from rest_framework import serializers
from .serializers import ContactUsSerailizer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail

@api_view(['POST','GET'])
def contact_us(request):
    serializer = ContactUsSerailizer(data=request.data)
    if serializer.is_valid(raise_exception = True):
        sender = serializer.validated_data['sender']
        message = serializer.validated_data['message']
        send_mail(
            subject = 'Contact Form mail ' ,
            message = message,
            from_email= sender,
            recipient_list=
            ['housefree189@gmail.com'],
            fail_silently=False
        )
        return Response({
        'message':'Thank you for your message, we will get back to you shortyly'}, 
        status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)