from django.contrib import admin
from .models import Logins
from .forms import LoginsForm


@admin.register(Logins)
class LoginsAdmin(admin.ModelAdmin):
    form = LoginsForm
    list_display = ('service', 'login', 'updated_at', 'created_at')
    search_fields = ('service', 'login')
