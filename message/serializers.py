import email
from email import message
from rest_framework import serializers
from datetime import datetime
def message_serializer(a) -> dict:
    return{
        "author": a.author,
        "message": a.message,
        "timestamp": (a.timestamp).strftime("%a. %I:%M %p"),
        "short_id": a.short_id
    }

class ContactUsSerailizer(serializers.Serializer):
    sender = serializers.EmailField()
    message = serializers.CharField()


    def __str__(self):
        return self.sender