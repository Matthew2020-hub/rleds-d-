from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator

password_regex_pattern = RegexValidator(
    regex=r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*+=]).{8,}$",
    message={
        "password": "Your Password Is Weak",
        "Hint":"Min. 8 character, 1 letter, 1 number and 1 special character",
    },
)


def minimum_amount(value):
    if value < 0:
        raise ValidationError("The minimum amount is 0")
