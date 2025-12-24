from django.urls import path
from django.contrib.auth import views as auth_views
from .views import home_view, create_login, get_login, update_login, delete_login, get_password

app_name = 'app'

urlpatterns = [
    path('', home_view, name='home'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='app:login'), name='logout'),
    path('api/login/create/', create_login, name='create_login'),
    path('api/login/<int:login_id>/', get_login, name='login_details'),
    path('api/login/<int:login_id>/update/', update_login, name='update_login'),
    path('api/login/<int:login_id>/delete/', delete_login, name='delete_login'),
    path('api/password/<int:login_id>/', get_password, name='get_password'),
]
