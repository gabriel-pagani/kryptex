from django.urls import path
from .views import home_view, get_password_api, create_login_api

app_name = 'app'

urlpatterns = [
    path('', home_view, name='home'),
    path('api/password/<int:login_id>/', get_password_api, name='get_password'),
    path('api/login/create/', create_login_api, name='create_login'),
]
