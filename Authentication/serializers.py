from .models import User, VerifyCode
from rest_framework import serializers
from message.models import Room
from transaction.models import Rooms
from .validators import password_regex_pattern


class CustomUserSerializer(serializers.ModelSerializer):

    """A User serializer"""

    password = serializers.CharField(
        validators=[password_regex_pattern],
        max_length=100,
        style={"input_type": "password"},
        write_only=True,
    )

    class Meta:
        model = User
        fields = [
            "email",
            "entry",
            "password",
            "name",
            "country",
            "phone_number",
            "user_id",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "password2": {"write_only": True},
        }

    def save(self):
        user = User(
            email=self.validated_data["email"],
            name=self.validated_data["name"],
            country=self.validated_data["country"],
            phone_number=self.validated_data["phone_number"],
        )
        password = self.validated_data["password"]
        user.set_password(password)
        user.entry = "Tenant"
        # Room.objects.get_or_create(user=user)
        return super().save()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False
    )

    class Meta:
        ref_name = "my_login"

    def __str__(self):
        return self.email


class CustomPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        validators=[password_regex_pattern],
        max_length=100,
        min_length=8,
        style={"input_type": "password"},
        write_only=True,
    )


class GetAcessTokenSerializer(serializers.Serializer):
    """Serializer which gets access token from Google"""

    code = serializers.CharField()


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()

    def __str__(self):
        return self.code


class VerifyCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerifyCode
        fields = "__all__"


class AgentSerializer(serializers.ModelSerializer):
    """An agent serializer class"""

    password = serializers.CharField(
        validators=[password_regex_pattern],
        style={"input_type": "password"},
        write_only=True,
    )

    class Meta:
        model = User
        fields = [
            "email",
            "entry",
            "password",
            "name",
            "country",
            "phone_number",
            "agent_location",
            "user_id",
        ]

    def save(self):
        user = User(
            email=self.validated_data["email"],
            name=self.validated_data["name"],
            country=self.validated_data["country"],
            phone_number=self.validated_data["phone_number"],
            agent_location=self.validated_data["agent_location"],
        )
        password = self.validated_data["password"]
        user.set_password(password)
        user.entry = "Agent"
        return super().save()


class GenrateOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def __str__(self):
        return self.email
