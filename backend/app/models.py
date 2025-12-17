from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from .validators import valid_cpf, valid_phone, valid_zipcode


class Users(AbstractUser):
    STATES = [
        ('AC', 'Acre'),
        ('AL', 'Alagoas'),
        ('AP', 'Amapá'),
        ('AM', 'Amazonas'),
        ('BA', 'Bahia'),
        ('CE', 'Ceará'),
        ('DF', 'Distrito Federal'),
        ('ES', 'Espírito Santo'),
        ('GO', 'Goiás'),
        ('MA', 'Maranhão'),
        ('MT', 'Mato Grosso'),
        ('MS', 'Mato Grosso do Sul'),
        ('MG', 'Minas Gerais'),
        ('PA', 'Pará'),
        ('PB', 'Paraíba'),
        ('PR', 'Paraná'),
        ('PE', 'Pernambuco'),
        ('PI', 'Piauí'),
        ('RJ', 'Rio de Janeiro'),
        ('RN', 'Rio Grande do Norte'),
        ('RS', 'Rio Grande do Sul'),
        ('RO', 'Rondônia'),
        ('RR', 'Roraima'),
        ('SC', 'Santa Catarina'),
        ('SP', 'São Paulo'),
        ('SE', 'Sergipe'),
        ('TO', 'Tocantins'),
    ]
    
    email = models.EmailField(blank=True, null=True)
    cpf = models.CharField(max_length=11, blank=True, null=True, validators=[valid_cpf])
    phone = models.CharField(max_length=11, blank=True, null=True, validators=[valid_phone])
    date_birth = models.DateField(blank=True, null=True)
    street = models.CharField(max_length=100, blank=True, null=True)
    number = models.CharField(max_length=25, blank=True, null=True)
    complement = models.CharField(max_length=200, blank=True, null=True)
    neighborhood = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=2, blank=True, null=True, choices=STATES)
    zip_code = models.CharField(max_length=8, blank=True, null=True, validators=[valid_zipcode])
    observations = models.TextField(blank=True, null=True)

    def clean(self):
        super().clean()
        if self.email:
            email = Users.objects.filter(email=self.email).exclude(pk=self.pk)
            if email.exists():
                raise ValidationError({'email': 'A user with this email already exists.'})


class Credential(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE, verbose_name="Usuário")
    service_name = models.CharField(max_length=100, verbose_name="Serviço")
    username = models.CharField(max_length=100, verbose_name="Usuário/Email")
    encrypted_password = models.TextField(verbose_name="Senha Criptografada", blank=True, null=True)
    website_url = models.URLField(blank=True, null=True, verbose_name="URL")
    notes = models.TextField(blank=True, null=True, verbose_name="Observações")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.service_name} ({self.username})"

    class Meta:
        verbose_name = "Credencial"
        verbose_name_plural = "Credenciais"
