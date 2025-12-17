from django import forms
from .models import Logins
from .crypto import decrypt_text


class LoginsForm(forms.ModelForm):
    password = forms.CharField(
        required=False, 
        widget=forms.TextInput(attrs={'class': 'vLargeTextField'})
    )

    class Meta:
        model = Logins
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            decrypted = decrypt_text(self.instance.password)
            if decrypted != "[Erro na descriptografia]":
                self.initial['password'] = decrypted
            else:
                self.initial['password'] = self.instance.password
