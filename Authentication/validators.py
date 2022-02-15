from django.core.exceptions import ValidationError


def minimum_amount(value):
    if value < 0:
        raise ValidationError("The minimum amount is 0")