from ast import mod
from distutils.command.upload import upload
from email.mime import image
from email.policy import default
from multiprocessing.dummy import Array
from django.db import models
from django.db import models
import uuid
from cloudinary.models import CloudinaryField
from django.contrib.postgres.fields import ArrayField
from django.forms import JSONField




class Apartment(models.Model):
    
    CATEGORY_TYPE = [
        ('Bungalow','Bungalow'),
        ('Duplex','Duplex'),
        ('Flats','Flats'),
        ('Self Contain','Self Contain')
    ]
    apartment_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    apartment_title = models.CharField(max_length=40, null=False, verbose_name='Apartment Title')
    category = models.CharField(choices=CATEGORY_TYPE, max_length=20)
    videofile = models.FileField(upload_to='video/', blank=False, null=True)
    price = models.CharField(max_length=50, null=False)
    location = models.CharField(max_length=30, null=False)
    agent = models.CharField(max_length=30, null=True)
    descriptions = models.CharField(max_length=250, blank=False)
    feautures = models.CharField(max_length=250, blank=False)
    location_info = models.CharField(max_length=250, blank=False)
    is_available = models.BooleanField(default=True)

    class Meta:
        ordering = ['category']

    # @property
    # def choices(self):
    #     return self.choice_set.all()

class Media(models.Model):
    image_url = models.URLField(max_length=500, blank=False)
    apartment = models.ForeignKey(Apartment, on_delete=models.CASCADE, related_name="image_url")
