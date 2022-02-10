from django.db import models
import uuid
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


class Withdrawal(models.Model):
    account_number = models.CharField(max_length=20)
    account_bank = models.CharField(max_length=4)
    amount = models.CharField(max_length=20)
    narration = models.CharField(max_length=200)
    currency_choice = [
        ('USD', 'USD'),
        ('NGN', 'NGN')
    ]
    debit_choice = [
        ('USD', 'USD'),
        ('NGN', 'NGN')
    ]
    currency = models.CharField(choices=currency_choice,  max_length=3)
    reference = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    email = models.EmailField()
    debit_currency = models.CharField(choices=debit_choice, max_length=3)
    account_id = models.CharField(max_length=60)
    withdrawal_date = models.DateTimeField()