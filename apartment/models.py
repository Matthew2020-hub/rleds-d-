from distutils.command.upload import upload
from django.db import models

# Create your models here.
from django.db import models
import uuid
from cloudinary.models import CloudinaryField
# msemsms
# Create your models here.
class Apartment(models.Model):
    
    apartment_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    name = models.CharField(max_length=40, null=True)
    category = models.CharField(max_length=50, null=True)
    image = models.ImageField(upload_to='apartment/', blank=True)
    price = models.CharField(max_length=50, null=True)
    location = models.CharField(max_length=30, null=True)
    agent = models.CharField(max_length=30, null=True)

    class Meta:
        ordering = ['category']