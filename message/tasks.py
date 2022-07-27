from .serializers import ContactUsSerailizer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from time import sleep
from celery import shared_task


@shared_task
def sleepy(duration):
    sleep(duration)
    return None


@shared_task
@api_view(["POST", "GET"])
def contact_us(request):
    sleep(2)
    serializer = ContactUsSerailizer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        sender = serializer.validated_data["sender"]
        message = serializer.validated_data["message"]
        send_mail(
            subject="Contact Form mail ",
            message=message,
            from_email=sender,
            recipient_list=["free_house@yahoo.com"],
            fail_silently=False,
        )
        return Response(
            {"message": "Thank you for your message, we will get back to you shortyly"},
            status=status.HTTP_200_OK,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
