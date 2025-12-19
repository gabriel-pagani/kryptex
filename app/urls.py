from django.urls import path
from .views import home_view, get_password_api

app_name = 'app'

urlpatterns = [
    path('', home_view, name='home'),
    path('api/password/<int:login_id>/', get_password_api, name='get_password'),
]
