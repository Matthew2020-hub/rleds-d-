import email
from email import message
from rest_framework import serializers

class ContactUsSerailizer(serializers.Serializer):
    sender = serializers.EmailField()
    message = serializers.CharField()


    def __str__(self):
        return self.sender