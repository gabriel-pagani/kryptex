from django.db import models


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
    is_fav = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.service

    class Meta:
        verbose_name = "Login"
        verbose_name_plural = "Logins"
        ordering = ['service',]
