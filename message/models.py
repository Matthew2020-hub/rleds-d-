from django.db import models
from django.conf import settings
# from django.contrib.auth.models import User
import uuid
# Create your models here.
class Message(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    short_id = models.UUIDField(default=uuid.uuid4, primary_key=True, unique=True)

    def __str__(self):
        return self.author