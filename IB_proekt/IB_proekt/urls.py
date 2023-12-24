"""
URL configuration for IB_proekt project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from pet_shop import views

urlpatterns = [
    path('admin/', admin.site.urls),
    # path('home/', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('logout_form/', views.logout_form, name='logout_form'),
    path('login/', views.login_form, name='login_form'),
    path('verify_email/<str:username>/', views.verify_email, name='verify_email'),
    path('two_factor_authentication', views.two_factor_authentication, name='two_factor_authentication'),

    path('posts/', views.home, name='posts'),
    path('posts/search/', views.search_results, name='search_results'),
    path('posts/filter/', views.filter_results, name='filter_results'),
    path('posts/view/<int:post_id>/', views.view, name='view_post'),
    path('add/post/', views.create, name='create'),
    path('posts/comment_on_post/<int:post_id>/', views.comment_on_post, name='comment_on_post'),
    path('posts/edit/<int:post_id>/', views.edit, name='edit_post'),
    path('posts/delete/<int:post_id>/', views.delete, name='delete_post'),
    path('posts/delete_comment/<int:comment_id>/', views.delete_comment, name='delete_comment'),
    path('blockedUsers/', views.blocked, name='blocked'),
    path('profile/', views.profile, name='profile'),
    path('users/', views.list_users, name='list_users'),
    path('change_role/', views.change_role, name='change_role'),

]

