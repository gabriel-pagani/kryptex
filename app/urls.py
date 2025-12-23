from django.urls import path
from django.contrib.auth import views as auth_views
from .views import home_view, get_password_api, create_login_api, get_login_details_api, update_login_api, delete_login_api

app_name = 'app'

urlpatterns = [
    path('', home_view, name='home'),
    # path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    # path('logout/', auth_views.LogoutView.as_view(next_page='app:login'), name='logout'),
    path('api/password/<int:login_id>/', get_password_api, name='get_password'),
    path('api/login/create/', create_login_api, name='create_login'),
    path('api/login/<int:login_id>/details/', get_login_details_api, name='login_details'),
    path('api/login/<int:login_id>/update/', update_login_api, name='update_login'),
    path('api/login/<int:login_id>/delete/', delete_login_api, name='delete_login'),
]
