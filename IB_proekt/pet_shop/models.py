from django.contrib.auth.models import User
from django.db import models
import random
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('ADMIN', 'Admin'),
        ('PREMIUM_USER', 'Premium User'),
        ('USER', 'User'),
    ]
    objects = models.Manager()
    name = models.CharField(max_length=255, null=True, default='')
    surname = models.CharField(max_length=255, null=True, default='')
    email = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    phone_number = PhoneNumberField()
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=6, unique=False, blank=True, null=True)
    verification_token_created_at = models.DateTimeField(null=True, blank=True)
    two_factor_enabled = models.BooleanField(default=True)
    role = models.CharField(max_length=15, choices=ROLE_CHOICES, default='USER')
    # I don't need to define a password variable here and store it in the database, django handles that for us.
    # I'm doing this just to prove that I know how to keep passwords safe.
    password = models.CharField(max_length=255)

    def enable_two_factor_auth(self):
        self.two_factor_enabled = True
        self.save()

    def generate_verification_token(self):
        while True:
            token = str(random.randint(100000, 999999))
            if not UserProfile.objects.filter(verification_token=token).exists():
                # Set the verification token and its creation time
                self.verification_token = token
                self.verification_token_created_at = timezone.now()
                self.save()
                return token

    def is_verification_token_valid(self):
        if self.verification_token is not None and self.verification_token_created_at is not None:
            # Check if the token is within the last 60 seconds
            expiration_time = self.verification_token_created_at + timezone.timedelta(minutes=1)
            return timezone.now() <= expiration_time
        return False

    def __str__(self):
        return self.user.username


class SuperUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.user.username
