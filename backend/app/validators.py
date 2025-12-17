from django.core.exceptions import ValidationError


def valid_cpf(value):
    if len(value) != 11 or value == value[0] * 11 or not value.isdigit():
        raise ValidationError('Enter a valid CPF.')

    sum1 = digit1 = 0
    for i in range(9):
        sum1 += int(value[i]) * (10 - i)
    digit1 = 11 - (sum1 % 11)
    if digit1 >= 10:
        digit1 = 0

    sum2 = digit2 = 0
    for i in range(10):
        sum2 += int(value[i]) * (11 - i)
    digit2 = 11 - (sum2 % 11)
    if digit2 >= 10:
        digit2 = 0

    if int(value[9]) != digit1 or int(value[10]) != digit2:
        raise ValidationError('Enter a valid CPF.')


def valid_phone(value):
    if not value.isdigit():
        raise ValidationError('This field must contain only numbers.')

    if len(value) < 10:
        raise ValidationError('This field must contain at least 10 digits.')


def valid_zipcode(value):
    if not value.isdigit():
        raise ValidationError('This field must contain only numbers.')

    if len(value) != 8:
        raise ValidationError('This field must contain exactly 8 digits.')
