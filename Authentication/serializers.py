from .models import User, VerifyCode
from rest_framework import serializers

# from message.models import Room
from .validators import password_regex_pattern
class CustomUserSerializer(serializers.ModelSerializer):

    """A User serializer"""
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
            "user_id",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "password2": {"write_only": True},
        }



class SigninSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False
    )

    # class Meta:
    #     ref_name = "my_login"

    # def __str__(self):
    #     return self.email


class CustomPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
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

 


class GenrateOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def __str__(self):
        return self.email
