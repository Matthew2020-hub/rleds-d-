from django.db import models
from django.conf import settings
# Create your models here.

class Profile(models.Model):
    # user_profile = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=40,   blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    Location = models.CharField(max_length=40, null=True, blank=True)
    profile_image = models.ImageField(upload_to = 'profile/', blank=True ,null=True)
    background_image = models.ImageField(upload_to = 'profile/', blank=True ,null=True)