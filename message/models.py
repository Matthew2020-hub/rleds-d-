from email import message
from django.db import models
from django.conf import settings
# from django.contrib.auth.models import User
import uuid
# Create your models here.
class Message(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField(unique=False, blank= False)
    timestamp = models.DateTimeField(auto_now_add=True)
    short_id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True)

class MessageManager(models.Manager):
    def by_room(self, room):
        qs = Message.objects.filter(room=room).order_by("-timestamp")
        return qs

    def __str__(self):
        return self.content
class PrivateRoom(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    messages = models.ForeignKey(Message, on_delete= models.CASCADE)
    send_file = models.FileField()

    def __str__(self):
        return self.user