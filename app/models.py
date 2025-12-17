from django.db import models
from django.contrib.auth.models import User


class Credential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Usuário")
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
