from django import forms
from django.contrib.auth.models import User

from pet_shop.models import UserProfile, Comment, BlogPost
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
    code = forms.CharField(label="Code", max_length=100)


class PostForm(forms.ModelForm):
    # files = forms.FileField(required=False)
    blocked_users = forms.ModelMultipleChoiceField(queryset=User.objects.all(), required=False)

    def __init__(self, *args, **kwargs):
        super(PostForm, self).__init__(*args, **kwargs)
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"

    class Meta:
        model = BlogPost
        exclude = ("author",)


class CommentForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CommentForm, self).__init__(*args, **kwargs)
        for field in self.visible_fields():
            field.field.widget.attrs["class"] = "form-control"

    class Meta:
        model = Comment
        exclude = ("author", "blog_post")


class BlockForm(forms.Form):
    username = forms.CharField(max_length=150)

    def __init__(self, *args, **kwargs):
        super(BlockForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['class'] = 'form-control'
