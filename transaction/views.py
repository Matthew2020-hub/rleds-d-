from django.shortcuts import render

# Create your views here.
from locale import currency
from multiprocessing import AuthenticationError
import re
from unicodedata import name
from django.forms import ValidationError
from django.http import request
from django.shortcuts import render
from userAuthentication.models import User
from .models import Payment
from .serializers import PaymentSerializer, VerifyPaymentSerializer, WithdrawalSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from random import randint
from django.contrib.auth.decorators import login_required
import environ
import requests
from dev.settings import FLUTTERWAVE_KEY


@api_view(['GET', 'POST'])
def make_payment(request):
    # queryset = Payment.objects.all()
    serializer = PaymentSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        email = serializer.validated_data['email']
        amount = serializer.validated_data['amount']
        phone = serializer.validated_data['phone']
        name = serializer.validated_data['name']
        agent_account_no = serializer.validated_data['agent_account_number']
        # query = User.objects.filter(entry='agent')
        verify_acct = User.objects.get(user_id = agent_account_no)
        if verify_acct is not None:
            print(verify_acct)
            acc = verify_acct.balance
            print(acc)
            acc += float(amount)
            print(acc)
            verify_acct.save()
            print(verify_acct.balance)
            auth_token = FLUTTERWAVE_KEY
            hed = {'Authorization': 'Bearer ' + auth_token}
            data = {
                        "tx_ref":''+str(randint(111111,999999)),
                        "amount":amount,
                        "currency":"NGN",
                        "redirect_url":"http://localhost:8000/view/",
                        "payment_options":"card",
                        "meta":{
                                "consumer_id":agent_account_no,
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
        raise AuthenticationError('no valid user')

@api_view(['GET','POST']) 
def verify_transaction(self, transaction_id): 
    response = requests.get(
        f'https://api.flutterwave.com/v3/transactions/{transaction_id}/verify',
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {FLUTTERWAVE_KEY}'},
    )
    json_response = response.json()
    response_data = json_response['data']
    if response_data['status'] == 'successful':
        amount = response_data['amount']
        agent = response_data['meta']['consumer_id']
        verify = User.objects.get(user_id=agent)
        verify.balance +=amount
        verify.save()
        print(verify.balance) 
        return Response(response_data)
    return Response ('Payment not successful', status=status.HTTP_400_BAD_REQUEST)

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
        print(account_id.balance)
        # email_verify = account_id.get(email=email)
        if account_id.email !=email:
            return Response({'message':'Invalid Email input, enter the correct email!'}, status=status.HTTP_404_NOT_FOUND)
        elif account_id is None:
            return Response({'message':'Incorrect Account ID!'}, status=status.HTTP_404_NOT_FOUND) 
        elif int(amount) > int(account_id.balance):
            raise ValueError("Insufficient fund")
        auth_token = FLUTTERWAVE_KEY
        header = {'Authorization': 'Bearer ' + auth_token}
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
        response = requests.post(url, json=data, headers=header)
        response_data = response.json()
        return Response(response_data)

# @login_required
def dashboard(request):
    
    print(request.user)
    wallet_balance = User.objects.get(user=request.user).balance
    if not wallet_balance is None:
        print(request.user)
        context = {
            'wallet': wallet_balance
        }
        return Response(context, status=status.HTTP_200_OK)
    else:
        return ValidationError('error')

