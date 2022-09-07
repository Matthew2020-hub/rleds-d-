from multiprocessing import AuthenticationError
from django.forms import ValidationError
from .serializers import (
    SigninSerializer,
    GetAcessTokenSerializer,
    CustomPasswordResetSerializer,
    AgentSerializer,
    CustomUserSerializer,
    GenrateOTPSerializer,
    VerifyOTPSerializer,
)
from .models import User, VerifyCode

# from message.models import Room
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (
    api_view,
    permission_classes, authentication_classes
)
from django.contrib.auth import login
from django.db import IntegrityError
from django.utils.translation import gettext_lazy as _
import requests
import jwt, datetime
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.utils.http import unquote
from drf_yasg.utils import swagger_auto_schema
import os
import environ
from django.core.exceptions import ValidationError
from rest_framework.exceptions import APIException
from random import randint
from datetime import datetime, timedelta
from mailjet_rest import Client
from django.utils import timezone

env = environ.Env()
environ.Env.read_env("housefree.env")
from_email = os.environ.get("EMAIL_HOST_USER")
api_key = os.environ.get("MJ_API_KEY")
api_secret = os.environ.get("MJ_API_SECRET")
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_NUMBER = os.environ.get("TWILIO_NUMBER")
GOOGLE_TOKEN_URL = os.environ.get("GOOGLE_TOKEN_URL")
SOCIAL_AUTH_GOOGLE_KEY = os.environ.get("GOOGLE_CLIENT_ID")
SOCIAL_AUTH_GOOGLE_SECRET = os.environ.get("GOOGLE_CLIENT_KEY")
redirect_uri = os.environ.get("redirect_uri")
project_id = os.environ.get("project_id")


class UserList(APIView):

    """
    An endpoint that returns a list of all users

    Returns: HTTP_200_OK and a list of available user

    Raises: HTTP_204_NO_CONTENT- if there's no registered or active user
    """

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request):
        queryset = User.objects.filter(entry="Tenant")
        if not queryset:
            return Response(
                "No registered user in the database",
                status=status.HTTP_204_NO_CONTENT,
            )
        get_all_users = CustomUserSerializer(queryset, many=True)
        return Response(get_all_users.data, status=status.HTTP_200_OK)


class userRegistration(APIView):
    """
    A user registration class
    A token is being created for a user after a successful registration

    Returns: HTTP_201_CREATED, a serializer data and a token
    Raises:
        HTTP_500_INTERNAL_SERVER_ERROR if user's data couldn't be processed
        HTTP_400_BAD_REQUEST if there's an invalid data or a unique constraint

    """

    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=CustomUserSerializer)
    def post(self, request):
        try:
            serializer = CustomUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_create = User.objects.create_user(
                **serializer.validated_data
            )
            if not user_create:
                return Response(
                    "User creation is unsuccessful",
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            return Response(
                {"message": "Check your email for verification"},
                status=status.HTTP_201_CREATED,
            )
        except IntegrityError as error:
            raise APIException(detail=error)


class agentRegistration(APIView):
    """
    An agent registration class
    A token is being created for an agent after a successful registration

    Returns: HTTP_201_CREATED- a serializer data and a token
    Raise:
        HTTP_500_INTERNAL_SERVER_ERROR if agent's data couldn't be processed
        HTTP_400_BAD_REQUEST if there is an invalid data or unique constraint

    """

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]

    @swagger_auto_schema(request_body=AgentSerializer)
    def post(self, request):
        try:
            serializer = AgentSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            agent_create = User.objects.create_user(**serializer.validated_data)
            if not agent_create:
                return Response('Agent creation is unsuccessful', 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            return Response(
                {"message": "Check your email and verify"},
                status=status.HTTP_201_CREATED,
            )
        except IntegrityError as error:
            raise APIException(detail=error)




@api_view(["GET"])
@permission_classes([AllowAny])
def refreshToken(request, email):

    """
    A Refresh Token class for email verifcation
    A JWT refresh token is created for email verification
    and the token is sent to user's email using MAILJET
    Args:
        email- a user email is provided
    Returns: HTTP_201_created, mailjet data

    Raises: (i) HTTP_404_NOT_FOUND if email doesn't exist
            (ii) HTTP_422_UNPROCESSABLE_ENTITY- if mailjet 
            couldn't send the email
    """

    user = get_object_or_404(User, email=email)
    if user.is_verify is True:
        return Response(
            "User's Email already verified",
            status=status.HTTP_208_ALREADY_REPORTED
        )

    email_verification_token = RefreshToken.for_user(user).access_token
    current_site = get_current_site(request).domain
    print(current_site)
    absurl = f"https://freehouses.herokuapp.com/api/v1/email-verify?token={email_verification_token}"
    email_body = (
        "Hi " + " " + user.name + ":\n" + "Use link below to verify your email"
        "\n" + absurl
    )
    data = {
        "email_body": email_body,
        "to_email": user.email,
        "subject": "Verify your email",
    }
    mailjet = Client(auth=(api_key, api_secret), version="v3.1")
    data = {
        "Messages": [
            {
                "From": {
                    "Email": f"akinolatolulope24@gmail.com",
                    "Name": "freehouse",
                },
                "To": [{"Email": f"{user.email}", "Name": f"{user.name}"}],
                "Subject": "Email Verification",
                "TextPart": "Click on the below link to verify your Email!",
                "HTMLPart": email_body,
            }
        ]
    }
    mailjet_result = mailjet.send.create(data=data)
    if mailjet_result:
        return Response(mailjet_result.json(), status=status.HTTP_201_CREATED)
    return Response(
        "Email couldn't be sent, try again",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )


class VerifyEmail(APIView):
    """Verify Email class
    verifies user email by verifying the JWT token
    Args:
        JWT-refresh-token. Gets the token from the request
    Response:
        HTTP_200_OK- if the token is genuine and user with the token exists
    Raise:
        HTTP_404_NOT_FOUND- if there's no user with such token
        HTTP_400_BAD_REQUEST- if Token as expired or Token is invalid
    """

    permisssion_classes = [AllowAny]

    def get(self, request):

        token = request.GET.get("token")
        access_token_str = str(token)
        try:
            # access token verification
            access_token_obj = AccessToken(access_token_str)
        except Exception as e:
            return Response(
                "No token Input or Token already expired",
                status=status.HTTP_400_BAD_REQUEST,
            )
        user_id = access_token_obj["user_id"]
        user = get_object_or_404(User, user_id=user_id)
        if not user.is_verify:
            user.is_verify = True
            user.save()
        return Response(
            {"email": "Email verification is successful"},
            status=status.HTTP_200_OK,
        )


class ListAgent(APIView):

    """An endpoint that returns a list of all AGENT

    Returns: HTTP_200_OK- a list of available AGENT

    Raises: HTTP_404_NOT_FOUND- if there's no registered AGENT
    """

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request):
        queryset = User.objects.filter(entry="Agent")
        if not queryset:
            # return no content if there's no registered agent
            return Response(
                "No available agent", status=status.HTTP_204_NO_CONTENT
            )
        get_all_agents = CustomUserSerializer(queryset, many=True).data
        return Response(get_all_agents, status=status.HTTP_200_OK)


class GET_AND_DELETE_User(APIView):
    """
    An endpoint to GET or delete a user's record
    Returns a user object
    Args:
        Email- returns a user data that was provided during registration
    Response:
        HTTP_200_OK, a serailizer data if user exists
    Raise:
        HTTP_404- returns not found if a user with the email doesn't exist
    """
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request, email):
        user = get_object_or_404(User, email=email)
        return Response(
            CustomUserSerializer(user).data, 
            status=status.HTTP_200_OK
        )

    def delete(self, request, email):
       
        try:
            user = get_object_or_404(User, email=email)
            if user.is_admin is True:
                return Response(
                    "user is Admin cannot be deleted",
                    status=status.HTTP_400_BAD_REQUEST
                )
            token = Token.objects.get(user=user)
            token.delete()
            user.delete()
            return Response(
                "User is successfully deleted", 
                status=status.HTTP_204_NO_CONTENT
            )
        except Token.DoesNotExist:
            return Response("Invalid Token", status=status.HTTP_404_NOT_FOUND)


class GET_AND_DELETE_AGENT(APIView):

    """An endpoint to GET a specific agent object and DELETE agent's data
    Returns an AGENT object
    Args:
        Email- supplied as a path paramter argument for user verification
    Response:
        HTTP_200_OK, a serailizer data if AGENT's data exists
    Raise:
        HTTP_404- an erorr response if agent with email doesn't exist
    """

    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]

    def get(self, request, email):
        get_agent = get_object_or_404(User, email=email)
        serializer = AgentSerializer(get_agent)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, email):
        try:
            agent = get_object_or_404(User, email=email)
            if agent.is_admin is False:
                return Response(
                    "User is not an admin", 
                    status=status.HTTP_400_BAD_REQUEST
                    )
            token = Token.objects.get(user=agent)
            token.delete()
            agent.delete()
            return Response(
                "User is successfully deleted", 
                status=status.HTTP_204_NO_CONTENT
            )
        except Token.DoesNotExist:
            return Response("Invalid Token", status=status.HTTP_404_NOT_FOUND)


class GenerateOTP(APIView):
    """
    An OTP generating endpoint
    Args:
        Email- a serializer data (email)
    Response:
        HTTP_200_OK- a success response if email is sent successfully
    Raise:
        HTTP_404- an error response if user with email doe snot exist

    """

    permission_classes = [AllowAny]  # Allow everyone to register
    serializer_class = GenrateOTPSerializer

    @swagger_auto_schema(request_body=GenrateOTPSerializer)
    def post(self, request):
        code = randint(000000, 999999)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        check_user = get_object_or_404(User, email=email)
        if check_user.is_verify is False:
            return Response(
                "This user email has not been verified kindly\
                    return to the Registration page!",
                status=status.HTTP_401_UNAUTHORIZED,
            )
        # Genrated OTP must be created as an object in the database
        # OTP is unique for every user
        VerifyCode.objects.create(code=code)
        mailjet = Client(auth=(api_key, api_secret), version="v3.1")
        # OTP generated is sent to the User's email and clicking the email
        # will grant the user an access to change-password endpoint
        absurl = f"https://spokane-topaz.vercel.app/otp?email={email}"
        email_body = (
            "Hi " + " " + check_user.name + " " + f"this your OTP: {code}"
            "\n" + "Click on this link to change your password"
            "\n" + absurl
        )
        data = {
            "email_body": email_body,
            "to_email": check_user.email,
            "subject": "Reset Password Link",
        }
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": f"akinolatolulope24@gmail.com",
                        "Name": "freehouse",
                    },
                    "To": [
                        {
                            "Email": f"{check_user.email}",
                            "Name": f"{check_user.name}",
                        }
                    ],
                    "Subject": "Email Verification With OTP",
                    "TextPart": "This is your OTP below!",
                    "HTMLPart": email_body,
                }
            ]
        }
        mail_jet_result = mailjet.send.create(data=data)
        if not mail_jet_result:
            return Response(
                "Sending email failed",
                status=status.HTTP_422_UNPROCESSABLE_ENTITY
            )
        responses = mail_jet_result.json()
        return Response(
            {"message": "OTP sent, check your email"},
            status=status.HTTP_200_OK,
        )



class VerifyOTP(APIView):

    permission_classes = [AllowAny]
    @swagger_auto_schema(request_body=VerifyOTPSerializer)
    def post(self, request):

        """An endpoint to  verify OTP
        Password RESET OTP is verified
        Response:
            HTTP_200_OK- a success message if OTP is valid
        Raise:
            HTTP_406_NOT_ACCEPTABLE- an error message is OTP has expired
            HTTP_404_NOT_FOUND- error message if OTP supplied is invalid
        """
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data["otp"]
        verify_OTP = get_object_or_404(VerifyCode, code=otp)
        five_minutes_ago = timedelta(minutes=5)
        # 'timezone.utc' is used in datetime.now()
        # while trying to compare 2 different time
        current_time = datetime.now(timezone.utc)
        code_time_check = current_time - verify_OTP.add_time
        if code_time_check > five_minutes_ago:
            # The OTP expires after five minutes of it creation
            # OTP is deleted after expiration to keep DB clean
            verify_OTP.delete()
            return Response(
                " The verification code has expired ",
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        verify_OTP.delete()
        return Response("OTP is valid", status=status.HTTP_200_OK)


class PasswordReset(APIView):

    """A Password reset endpoint
        Args:
            Email- a path param retrieved from the URL
        Response:
            HTTP_200_OK response and a serailizer data
        Raise:
            HTTP_404 response if an user with the provided email \
                doesn't exist.
    """
    permisssion_classes = [AllowAny]
    @swagger_auto_schema(request_body=CustomPasswordResetSerializer)
    def put(self, request):
        serializer = CustomPasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data["password"]
        email = serializer.validated_data["email"]
        get_user = get_object_or_404(User, email=email)
        get_user.password = password
        get_user.set_password(password)
        get_user.save()
        return Response(
            "Password change is successful, return to login page",
            status=status.HTTP_200_OK,
        )


class Validate_Authorization_Code(APIView):

    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(request_body=GetAcessTokenSerializer)
    def post(self, request):

        """Login Athorization Endpoint With Google Token
        A google authorization key is decoded and user's info is verified
        Response:
            HTTP_200_OK response and a token is authorization is successful
        Raise:
            HTTP_404_NOT_FOUND response if user with email does not exist
        """
        serializer = GetAcessTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        authorization_code = serializer.validated_data["code"]
        # google authorization code is encoded which needs to be decoded before access_token
        # could be generated to retrieve logged-in user's info
        uncoded = unquote(authorization_code)
        if authorization_code is None:
            return Response(
                {"message": "Error occured due to Invalid authorization code"},
                status=status.HTTP_204_NO_CONTENT,
            )
        data = {
            "code": uncoded,
            "client_id": SOCIAL_AUTH_GOOGLE_KEY,
            "client_secret": SOCIAL_AUTH_GOOGLE_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        response = requests.post(f"{GOOGLE_TOKEN_URL}", data=data)
        if not response.ok:
            return Response(
                {"message": "Failed to obtain access token from Google"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        access_token = response.json()["access_token"]
        # retrieve user's info from google
        response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            params={"access_token": access_token},
        )
        if not response.ok:
            raise ValidationError("Failed to obtain user info from Google.")
        result = response.json()
        try:
            user_login = get_object_or_404(User, email=result["email"])
            token, created = Token.objects.get_or_create(user=user_login)
            return Response({"Token": token.key}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            raise AuthenticationError(
                "User with this email doesn't exist, kindly sign up"
            )


class Login(APIView):

    permission_classes = [AllowAny]
    @swagger_auto_schema(request_body=SigninSerializer)
    def post(self, request):

        """
        N.B: A custom user login endpoint
        Args:
            data: a serailizer data which contain user login credentials
        Response:
            HTTP_200_OK- a success response and user token
        Raise:
            HTTP_404_NOT_FOUND- if user with supplied email does not exist
            HTTP_401_UNAUTHORIZED- if login credentials are incorrect

        """
        serializer = SigninSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        user = get_object_or_404(User, email=email)
        print(user.password)
        user.backend = "django.contrib.auth.backends.ModelBackend"
        if not user.check_password(password):
            return Response(
                {"message": "Incorrect Login credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if not user.is_verify is True:
            user.is_verify is True
            # return Response({
            # 'message': 'Email is not yet verified, kindly do that!'},
            # status= status.HTTP_400_BAD_REQUEST
            # )
        token, created = Token.objects.get_or_create(user=user)
        login(request, user)
        return Response({"Token": token.key}, status=status.HTTP_200_OK)


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user_logout(request):
    """
    User logout Endpoint
    Logs out a user by deleteing the user token
    Response: 
        HTTP_200_OK- a response after user logout is successful
    Raise: 
        HTTP_404_NOT_FOUND- an error response if token provided is invalid
    """

    try:
        request.user.auth_token.delete()
        return Response(
            {"success": _("Successfully logged out.")},
            status=status.HTTP_200_OK,
        )
    except (Token.DoesNotExist):
        return Response(
            {"Error": _("Invalid Token, enter a valid token.")},
            status=status.HTTP_404_NOT_FOUND,
        )
