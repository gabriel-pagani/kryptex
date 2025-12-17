from django.db import models
from django.contrib.auth.models import User


class Logins(models.Model):
    service = models.CharField(max_length=100)
    login = models.CharField(max_length=100)
    password = models.TextField()
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = "Login"
        verbose_name_plural = "Logins"
