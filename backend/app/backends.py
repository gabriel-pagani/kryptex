from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model


class EmailModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None):
        User = get_user_model()
        try:
            user = User.objects.get(email=username)
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
            return None
        except User.DoesNotExist:
            return None
