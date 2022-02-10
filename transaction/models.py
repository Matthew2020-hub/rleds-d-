from django.db import models

from cmath import phase
import email
from email.policy import default
from django.conf import settings
from django.db import models
from django.conf import settings
from userAuthentication.models import User 
# Create your models here.

class Payment(models.Model):
    name = models.CharField(blank=False, max_length=30, verbose_name='name')
    email = models.EmailField(unique=True, verbose_name='email', blank=False)
    phone = models.CharField(max_length=12, unique=True, blank=False, verbose_name='phone number')
    date_created = models.DateTimeField(auto_now_add=True)
    amount = models.CharField(max_length=40, blank=False)
    agent_account_number = models.CharField(max_length=150, blank=False)

    def __str__(self):
        return self.agent_account_number
