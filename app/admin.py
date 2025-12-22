from django.contrib import admin
from .models import Logins, LoginTypes


admin.site.register(LoginTypes)


@admin.register(Logins)
class LoginsAdmin(admin.ModelAdmin):
    list_display = ('service', 'type', 'login', 'updated_at', 'created_at')
    search_fields = ('service', 'type__title', 'login')
    list_filter = ('type',)
