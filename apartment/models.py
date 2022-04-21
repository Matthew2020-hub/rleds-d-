from ast import mod
from distutils.command.upload import upload
from django.db import models
from django.db import models
import uuid
from cloudinary.models import CloudinaryField

class Apartment(models.Model):
    
    ORDER_TYPE = [
        ( 'All', 'All'),
        ('Active','Active'),
        ('Closed','Closed')
    ]
    order_type = models.CharField(choices=ORDER_TYPE, max_length=10)
    apartment_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    aparment_title = models.CharField(max_length=40, null=True, verbose_name='Apartment Title')
    category = models.CharField(max_length=50, null=True, blank=False)
    image = models.ImageField(upload_to='apartment/', blank=True)
    videofile = models.FileField(upload_to='video/', null=True, blank=True)
    price = models.CharField(max_length=50, null=True)
    location = models.CharField(max_length=30, null=True)
    agent = models.CharField(max_length=30, null=True)
    descriptions = models.CharField(max_length=250, blank=False, null=True)
    feautures = models.CharField(max_length=250, blank=False, null=True)
    location_info = models.CharField(max_length=250, blank=False, null=True)
    reviews = models.CharField(max_length=250, null=True)
    is_available = models.BooleanField(default=True)

    class Meta:
        ordering = ['category']