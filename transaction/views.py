from django.shortcuts import render
from locale import currency
from multiprocessing import AuthenticationError
import re
from unicodedata import name
from django.forms import ValidationError
from django.http import request
from django.shortcuts import render
from Authentication.models import User
from apartment.models import Apartment
from .models import Payment, PaymentHistory
from .serializers import HistorySerializer, PaymentSerializer, WithdrawalSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from random import randint
from django.contrib.auth.decorators import login_required
import environ
import requests
from dev.settings import FLUTTERWAVE_KEY
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny
from apartment.pagination import CustomPagination

@api_view(['GET', 'POST'])
def make_payment(request):
    serializer = PaymentSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        email = serializer.validated_data['email']
        amount = serializer.validated_data['amount']
        phone = serializer.validated_data['phone']
        name = serializer.validated_data['name']
        house_location = serializer.validated_data['House_location']
        try:
            verify_location = Apartment.objects.get(location = house_location)
        except Exception as e:
            return Response('Transaction failed due to incorrect house address. Try again', status=status.HTTP_400_BAD_REQUEST)
        if verify_location.is_available != True:
            return Response ('This Particular house is no more available', status=status.HTTP_204_NO_CONTENT)
        agent_account_no = serializer.validated_data['agent_account_number']
        verify_acct = User.objects.get(user_id = agent_account_no)
        if verify_acct is not None:
            auth_token = FLUTTERWAVE_KEY
            hed = {'Authorization': 'Bearer ' + auth_token}
            data = {
                "tx_ref":''+str(randint(111111,999999)),
                "amount":amount,
                "currency":"NGN",
                "redirect_url":"http://localhost:8000/api/v1/verify_transaction/",
                "payment_options":"card",
                "meta":{
                        "consumer_id":agent_account_no,
                        "house_location": house_location,
                        "consumer_mac":"92a3-912ba-1192a"
                        },
                "customer":{
                    "email":email,
                    "phonenumber":phone,
                    "name":name
                    },
                "customizations":{
                "title":"Supa houseFree",
                "description":"a user-agent connct platform",
                "logo":"https://getbootstrap.com/docs/4.0/assets/brand/bootstrap-solid.svg"
                    }
                }
            url = ' https://api.flutterwave.com/v3/payments'
            response = requests.post(url, json=data, headers=hed)
            response_data = response.json()
            link=response_data['data']['link']
            return Response(link)
        return Response('Agent with this Acoount ID does not exist!', status=status.HTTP_204_NO_CONTENT)


"""An endpoint to verify payment by calling futterwave's verification endpoint"""
@api_view(['GET','POST']) 
def verify_transaction(request, transaction_id): 
    response = requests.get(
        f'https://api.flutterwave.com/v3/transactions/{transaction_id}/verify',
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {FLUTTERWAVE_KEY}'},
    )
    json_response = response.json()
    response_data = json_response['data']
    if response_data['status'] == 'successful':
        amount = response_data['amount']
        agent = response_data['meta']['consumer_id']
        house_detail = response_data['meta']['house_location']
        verify_apartment = Apartment.objects.get(location = house_detail)
        if verify_apartment is not None:
            verify_apartment.is_available = False
            verify_apartment.save()
            verify = User.objects.get(user_id=agent)
            verify.balance +=amount
            verify.save()
            get_agent_name = User.objects.get(user_id=response_data['meta']['consumer_id'])
            if get_agent_name:
                recipient = get_agent_name.name
                receiver_number = response_data['meta']['consumer_id']
                amount = response_data['amount']
                date_sent = response_data['customer']['created_at']
                sender = response_data['customer']['name']
                transaction_status = 'Successful'
                create_history = PaymentHistory.objects.create(sender=sender, agent_account_number=receiver_number,
                date_sent=date_sent, amount=amount, recipient=recipient, transaction_status=transaction_status)
                create_history.save()
                return Response (response_data,status=status.HTTP_200_OK)
            recipient = get_agent_name.name
            receiver_number = response_data['meta']['consumer_id']
            amount = response_data['amount']
            date_sent = response_data['customer']['created_at']
            sender = response_data['customer']['name']
            transaction_status = 'Failed'
            create_history = PaymentHistory.objects.create(sender=sender, agent_account_number=receiver_number,
            date_sent=date_sent, amount=amount, recipient=recipient, transaction_status=transaction_status)
            create_history.save()
            verify_apartment.is_available = True
            verify_apartment.save()
        return Response('Transaction Failed!', status=status.HTTP_400_BAD_REQUEST)     
    return Response ('BAD REQUEST', status=status.HTTP_400_BAD_REQUEST)


"""An endpoint to list User's transaction history"""
class ApartmentCreateListAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin):
    serializer_class = HistorySerializer
    queryset = PaymentHistory.objects.all()
    lookup_field = 'history_id'
    permisssion_classes = [AllowAny]
    pagination_class = CustomPagination
    def get(self, request):
        check = PaymentHistory.objects.filter(sender=request.user.name)
        history = []
        for checkup in check:
            context = {
                'Sent to': checkup.recipient,
                'Agent account Number': checkup.agent_account_number,
                'Amount': checkup.amount,
                'Date': checkup.history_time,
                'Sent By': checkup.sender,
                'Transaction Status': checkup.transaction_status,
                'Alert Time': checkup.date_sent
            }
            history.append(context)
                
        return Response(history, status=status.HTTP_200_OK)

"""An endpoint through which an agent could withdraw from his wallet"""
@api_view(['GET', 'POST'])
def agent_withdrawal(request):
    serializer = WithdrawalSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        account_no = serializer.validated_data['account_number']
        account_bank = serializer.validated_data['account_bank']
        narration = serializer.validated_data['narration']
        currency = serializer.validated_data['currency']
        email = serializer.validated_data['email']
        amount = serializer.validated_data['amount']
        debit_currency = serializer.validated_data['debit_currency']
        acct_id = serializer.validated_data['account_id']
        account_id = User.objects.get(user_id=acct_id)
        if account_id.email !=email:
            return Response({'message':'Invalid Email input, enter the correct email!'}, status=status.HTTP_404_NOT_FOUND)
        elif account_id is None:
            return Response({'message':'Incorrect Account ID!'}, status=status.HTTP_404_NOT_FOUND) 
        elif int(amount) > int(account_id.balance):
            raise ValueError("Insufficient fund")
        auth_token = FLUTTERWAVE_KEY
        header = {'Content-Type':'application/json',
            'Authorization': f'Bearer {auth_token} ' }
        data = {
            "account_bank": account_bank,
            "account_number": account_no,
            "amount":amount,
            "narration": narration,
            "currency": currency,
            "currency":"NGN",
            "reference":''+str(randint(111111,999999)),
            "callback_url":"http://localhost:8000/view/",
            "debit_currency":debit_currency,
            }
        url = ' https://api.flutterwave.com/v3/transfers'
        response = requests.post(url, headers=header, params=data)
        response_data = response.json()
        return Response(response_data['status'])

"""An endpoint to get Agent's Wallet balance
"""
@api_view(['GET'])
def dashboard(request):
    wallet_balance = User.objects.get(email=request.user.email).balance
    if not wallet_balance is None:
        context = {
            'wallet': wallet_balance
        }
        return Response(context, status=status.HTTP_200_OK)
    else:
        message = {
            'Error': 'User does not have a valid wallet'
        }
        raise ValidationError(message, status=status.HTTP_204_NO_CONTENT)

