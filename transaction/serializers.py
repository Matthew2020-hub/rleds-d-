from dataclasses import fields
from datetime import datetime
import email
from email.policy import default
from django.forms import models
from .models import Payment, Withdrawal
import uuid
from rest_framework import serializers        
class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['amount', 'email','name', 'phone', 'agent_account_number' ]

class VerifyPaymentSerializer(serializers.Serializer):
    transaction_id = serializers.CharField()

class WithdrawalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Withdrawal
        fields = ['account_number', 'account_bank', 'amount', 'narration', 'currency', 'reference', 'email', 'debit_currency', 'account_id']
        
        def __str__(self):
            return self.amount