from django.db import models
import uuid


class Apartment(models.Model):

    CATEGORY_TYPE = [
        ("Bungalow", "Bungalow"),
        ("Duplex", "Duplex"),
        ("Flats", "Flats"),
        ("Self Contain", "Self Contain"),
    ]
    apartment_id = models.UUIDField(
        default=uuid.uuid4, editable=False, primary_key=True, unique=True
    )
    apartment_title = models.CharField(
        max_length=40, null=False, verbose_name="Apartment Title"
    )
    category = models.CharField(choices=CATEGORY_TYPE, max_length=20)
    videofile = models.CharField(max_length=500, blank=True, null=True)
    image_url = models.JSONField()
    price = models.CharField(max_length=50, null=False)
    location = models.CharField(max_length=30, null=False)
    agent = models.CharField(max_length=30, null=True)
    descriptions = models.CharField(max_length=250, null=True)
    feautures = models.CharField(max_length=250, blank=False, null=True)
    location_info = models.CharField(max_length=250, null=True)
    is_available = models.BooleanField(default=True)
    reviews = models.JSONField(null=True)

    class Meta:
        ordering = ["category"]
