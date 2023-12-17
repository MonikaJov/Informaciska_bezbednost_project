from django.contrib import admin

from pet_shop.models import UserProfile, SuperUser

# Register your models here.
admin.site.register(UserProfile)
admin.site.register(SuperUser)