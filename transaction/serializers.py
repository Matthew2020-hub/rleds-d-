from dataclasses import fields
from datetime import datetime
import email
from email.policy import default
from django.forms import models
from .models import Payment, PaymentHistory, Withdrawal
import uuid
from rest_framework import serializers        
class PaymentSerializer(serializers.ModelSerializer):
    House_location = serializers.CharField(max_length=150)
    class Meta:
        model = Payment
        fields = [
        'amount', 'email','name', 'phone', 
        'agent_account_number', 'House_location' 
        ]
        
def user_paymentHistory_serializer(a) -> dict:
    return{
        "room_id": a.room.room_id,
        "Sent By": a.sender,
        "Sent By": a.recipient,
        "Alert Time": a.date_sent,
        "agent_account_number": a.agent_account_number,
        "transaction_status": a.transaction_status,
        "Amount": a.amount,
        "Date": (a.history_time).strftime("%a. %I:%M %p"),
        "short_id": a.short_id
    }

class UserHistorySerializer(serializers.Serializer):
    class Meta:
        model = PaymentHistory
        fields = [
            'sender', 'recipient', 'phone', 'date_sent', 
            'agent_account_number', 'narration', 'reference', 
            'transaction_status', 'amount', 'history_time', 
            'short_id'
            ]

class WithdrawalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Withdrawal
        fields = [
            'account_number', 'account_bank', 'amount', 'narration', 
            'currency', 'reference', 'email', 'debit_currency', 
            'account_id'
            ]
        
        def __str__(self):
            return self.amount