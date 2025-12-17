from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from .models import Users, Credential
from .crypto import encrypt_text


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = Users
        fields = ('username',)


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = Users
        fields = '__all__'


class CredentialForm(forms.ModelForm):
    password_input = forms.CharField(
        label="Senha",
        required=False,
        widget=forms.PasswordInput(render_value=True),
        help_text="Digite uma nova senha aqui para alterar. Deixe em branco para manter a atual."
    )

    class Meta:
        model = Credential
        fields = '__all__'

    def save(self, commit=True):
        credential = super().save(commit=False)
        
        # Se o usuário digitou algo no campo de senha, criptografa e salva
        password = self.cleaned_data.get('password_input')
        if password:
            credential.encrypted_password = encrypt_text(password)
            
        if commit:
            credential.save()
        return credential

