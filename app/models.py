from django.db import models
from .crypto import encrypt_text, decrypt_text
import string
import secrets


class LoginTypes(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = "Login Type"
        verbose_name_plural = "Logins Types"
        ordering = ['title',]


class Logins(models.Model):
    service = models.CharField(max_length=100)
    type = models.ForeignKey(LoginTypes, on_delete=models.PROTECT, blank=True, null=True)
    login = models.CharField(max_length=100)
    password = models.TextField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_password = self.password

    def save(self, *args, **kwargs):
        if not self.password:
            alphabet = string.ascii_letters + string.digits + string.punctuation
            generated_password = ''.join(secrets.choice(alphabet) for _ in range(50))
            self.password = generated_password

        if self.pk is None or self.password != self._original_password:
            if self.password:
                self.password = encrypt_text(self.password)
        
        super().save(*args, **kwargs)
        self._original_password = self.password

    @property
    def decrypted_password(self):
        return decrypt_text(self.password)

    def __str__(self):
        return self.service

    class Meta:
        verbose_name = "Login"
        verbose_name_plural = "Logins"
        ordering = ['service',]
