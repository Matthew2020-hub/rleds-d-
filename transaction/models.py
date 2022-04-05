from django.db import models
import uuid
from cmath import phase
import email
from email.policy import default
from django.conf import settings
from django.db import models
from django.conf import settings
from django.dispatch import receiver
from Authentication.models import User 
from phonenumber_field.modelfields import PhoneNumberField
import uuid
import random
# Create your models here.

class Payment(models.Model):
    name = models.CharField(blank=False, max_length=30, verbose_name='name')
    email = models.EmailField(unique=True, verbose_name='email', blank=False)
    phone = PhoneNumberField(null=True, verbose_name='phone number')
    date_created = models.DateTimeField(auto_now_add=True)
    amount = models.CharField(max_length=40, blank=False)
    agent_account_number = models.CharField(max_length=150, blank=False)

    def __str__(self):
        return self.agent_account_number

def generate_short_id(size=9, chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    return ''.join(random.choice(chars) for _ in range(size))
class Rooms(models.Model):
    user = models.CharField(max_length=255, null=True)
    room_id = models.CharField(max_length=255, default=generate_short_id(), unique=True)

class PaymentHistory(models.Model):
    history_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, unique=True)
    room = models.ForeignKey(Rooms, related_name="messages",on_delete=models.CASCADE, null=True)
    sender = models.CharField(blank=False, max_length=30, null=True)
    recipient = models.CharField(max_length=60, blank=True, null=True)
    phone =  models.CharField(blank=False, max_length=30, null=True)
    date_sent = models.CharField(max_length=60, blank=True, null=True)
    amount = models.CharField(max_length=40, blank=False)
    agent_account_number = models.CharField(max_length=150, blank=False)
    account_number = models.CharField(max_length=20, null=True)
    history_time = models.DateTimeField(auto_now_add=True)
    account_bank = models.CharField(max_length=4, null=True)
    narration = models.CharField(max_length=200, null=True)
    reference = models.CharField(max_length=150, blank=True, null=True)
    debit_currency = models.CharField(null=True, max_length=3)
    account_id = models.CharField(max_length=60, blank=True, null=True)
    transaction_status = models.CharField(max_length=12, null=True)
    withdrawal_date = models.CharField(max_length=60, blank=True, null=True)
    short_id = models.CharField(max_length=255, default=generate_short_id(), unique=True)
    class Meta:
        ordering = ['-history_time']

class PaymentHistoryManager(models.Manager):
    def by_room(self, room):
        qs = PaymentHistory.objects.filter(room=room).order_by("-history_time")
        return qs

    def __str__(self):
        return self.transaction_status






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
    withdrawal_date = models.DateTimeField(auto_now_add=True)