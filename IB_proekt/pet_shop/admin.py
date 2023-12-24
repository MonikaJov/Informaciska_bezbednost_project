from django.contrib import admin

from pet_shop.models import UserProfile, SuperUser, BlogPost, Comment

# Register your models here.
admin.site.register(UserProfile)
admin.site.register(SuperUser)
admin.site.register(BlogPost)
admin.site.register(Comment)