from django import forms
from pet_shop.models import UserProfile
from phonenumber_field.formfields import PhoneNumberField

class LoginForm(forms.Form):
    your_username = forms.CharField(label="Username", max_length=100)
    your_password = forms.CharField(label="Password", max_length=100, widget=forms.PasswordInput)


class RegisterForm(forms.ModelForm):
    phone_number = PhoneNumberField()
    password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"

    class Meta:
        model = UserProfile
        fields = ['name', 'surname', 'email', 'address', 'phone_number', 'password']

class TwoFactorAuthenticationForm(forms.Form):
    code  = forms.CharField(label="Code", max_length=100)