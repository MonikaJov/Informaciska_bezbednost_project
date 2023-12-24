from django.contrib.auth.models import User
from django.core.validators import validate_email
from pet_shop.password_hasher_with_salt import PasswordHasher
from pet_shop.mailsender import MailSender
from django.contrib.auth import logout, authenticate, login
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from pet_shop.forms import LoginForm, RegisterForm
from django.shortcuts import render, redirect, get_object_or_404

from .forms import TwoFactorAuthenticationForm
from .models import UserProfile


def get_user(request):
    if request.user.is_authenticated:
        user = request.user
        return user
    else:
        session_key = request.session.session_key
        if not session_key:
            request.session.create()
            session_key = request.session.session_key
        user = User.objects.filter(username=session_key)[:1]
        if user.exists():
            print("User with username: ", session_key, " exists")
            user = user[0]
            return user
        else:
            user = User(username=session_key)
            user.set_password(session_key)
            user.save()
            return user


def home(request):

    if request.user.is_authenticated:
        user_profile = UserProfile.objects.get(user=request.user)
        context = {
            'user_profile': user_profile
        }
        return render(request, 'home.html', context)
    else:
        return redirect("login_form")


def logout_form(request):
    logout(request)
    print("Logging out")
    return redirect("home")


# NOTE: use password: theDOORisLOCKED4!!!
def login_form(request):
    if request.user.is_authenticated:
        return redirect("home")
    form = LoginForm()
    context = {'form': form}
    if request.method == "POST":
        form_data = LoginForm(data=request.POST, files=request.FILES)
        if form_data.is_valid():
            username = form_data.cleaned_data['your_username']
            password = form_data.cleaned_data['your_password']
            # here I'm checking if the password the user typed and the stored (hashed) password in the DB match
            try:
                # check if a user profile exists with that username
                user_profile = UserProfile.objects.get(user__username=username)
                # CHECK PASSWORD
                # if the passwords match then the user is logged in
                password_hasher = PasswordHasher()
                if password_hasher.check_password(password, user_profile.password):
                    # Check if two-factor authentication is enabled for the user
                    if user_profile.two_factor_enabled and user_profile.email_verified:
                        # Authenticate the user but don't log them in yet
                        user = authenticate(request, username=username, password=password)
                        # Set the user in the session to use later in two_factor_authentication view
                        request.session['username'] = username
                        # Redirect to the two-factor authentication view
                        return redirect('two_factor_authentication')

                    # Log in the user without two-factor authentication

                    user = authenticate(username=username, password=password)
                    login(request, user)
                    return redirect("home")
                # if the passwords don't match then show an error message
                else:
                    context = {
                        'form': LoginForm(),
                        'message2': "Invalid login credentials."
                    }
            except UserProfile.DoesNotExist:
                context = {
                    'form': LoginForm(),
                    'message2': "Invalid login credentials."
                }
        else:
            print(form.errors)
    return render(request, 'login.html', context)


def two_factor_authentication(request):
    username = request.session.get('username')
    if not username:
        return redirect('home')
    try:
        user_profile = UserProfile.objects.get(user__username=username)
        if request.method == 'POST':
            form = TwoFactorAuthenticationForm(request.POST)
            if form.is_valid():
                # TOKEN VALIDATION
                authentication_code = form.cleaned_data['code']
                if user_profile.is_verification_token_valid():
                    try:
                        # if the tokens match, verify user email
                        user_profile = UserProfile.objects.get(verification_token=authentication_code)
                        user_profile.save()
                        # Log in the user
                        login(request, user_profile.user)
                        return redirect('home')
                    except UserProfile.DoesNotExist:
                        context = {
                            'form': form,
                            'message': 'Invalid authentication code.',
                        }
                        return render(request, 'two_factor_authentication.html', context)
                else:
                    context = {
                        'form': form,
                        'message': 'Invalid authentication code.',
                    }
                    return render(request, 'two_factor_authentication.html', context)

        else:
            email = user_profile.email
            # Generate verification token
            authentication_code = user_profile.generate_verification_token()
            user_profile.verification_token = authentication_code
            user_profile.save()
            # SEND VERIFICATION TOKEN
            MailSender.send_email_for_verification(request, email, authentication_code)
            form = TwoFactorAuthenticationForm()

        context = {'form': form}
        return render(request, 'two_factor_authentication.html', context)
    except (UserProfile.DoesNotExist):
        return redirect('home')


def register(request):
    if request.user.is_authenticated:
        return redirect("home")
    form = RegisterForm()
    context = {'form': form, 'MEDIA_URL': settings.MEDIA_URL}
    if request.method == "POST":
        if request.user.is_authenticated:
            return redirect("home")
        form_data = RegisterForm(data=request.POST, files=request.FILES)
        if form_data.is_valid():
            user_profile = form_data.save(commit=False)
            username = request.POST.get('username')
            password2 = request.POST.get('password2')
            password = form_data.cleaned_data['password']
            email = form_data.cleaned_data['email']
            phone_number = form_data.cleaned_data['phone_number']
            # try and validate email
            try:
                validate_email(email)
            except ValidationError as e:
                form_data.add_error('email', e)
                context = {'form': form_data, 'MEDIA_URL': settings.MEDIA_URL}
                return render(request, 'register.html', context)
            # checking if the email already exists
            if UserProfile.objects.filter(email=email).exists():
                form_data.add_error('email', "This email address is already in use.")
                context = {'form': form_data, 'MEDIA_URL': settings.MEDIA_URL}
                print('Email already exists')
                return render(request, 'register.html', context)
            # checking if the phone number already exists
            if UserProfile.objects.filter(phone_number=phone_number).exists():
                form_data.add_error('phone_number', "This phone number is already in use.")
                context = {'form': form_data, 'MEDIA_URL': settings.MEDIA_URL}
                print('Phone number already exists')
                return render(request, 'register.html', context)
            # checking if the two passwords match
            if not password == password2:
                form_data.add_error('password', "Passwords do not match.")
                context = {'form': form_data, 'MEDIA_URL': settings.MEDIA_URL}
                return render(request, 'register.html', context) # if password can't be validated show the user an error message
            # try and validate password
            try:
                validate_password(password)
            except ValidationError as e:
                form_data.add_error('password', e)
                context = {'form': form_data, 'MEDIA_URL': settings.MEDIA_URL}
                # if password can't be validated show the user an error message
                return render(request, 'register.html', context)
            new_user = User.objects.create_user(username=username, email=email)
            new_user.set_password(password)
            new_user.save()
            user_profile.user = new_user
            user_profile.name = form_data.cleaned_data['name']
            user_profile.surname = form_data.cleaned_data['surname']
            user_profile.email = form_data.cleaned_data['email']
            user_profile.address = form_data.cleaned_data['address']
            user_profile.phone_number = phone_number
            # HASHING WITH SALT
            # in django manual hashing is not necessary
            # I'm doing this just to prove that I know how to keep passwords safe
            password_hasher = PasswordHasher()
            hashed_password = password_hasher.hash_password(password)
            user_profile.password = hashed_password
            # Generate verification token
            verification_token = user_profile.generate_verification_token()
            user_profile.verification_token = verification_token
            user_profile.save()
            if not user_profile.email_verified or not user_profile.is_verification_token_valid():
                # SEND VERIFICATION TOKEN
                MailSender.send_email_for_verification(request, email, verification_token)
                request.session['username_pom'] = username
                return render(request, 'verify_email.html', {'username': username})
        else:
            context = {'form': form_data, 'MEDIA_URL': settings.MEDIA_URL}
    return render(request, 'register.html', context)


def verify_email(request, username):
    if request.user.is_authenticated:
        return redirect("home")
    if request.method == "POST":
        # TOKEN VALIDATION
        token = request.POST.get('token')  # Retrieve the token from the POST data
        try:
            # if the tokens match, verify user email
            user_profile = UserProfile.objects.get(verification_token=token)
            if user_profile.is_verification_token_valid():
                user_profile.email_verified = True
                user_profile.save()
                context = {
                    'form': LoginForm(),
                    'message': "Your registration was successful"
                }
                return render(request, 'login.html', context)
            else:
                context = {
                    'message': "Invalid token or email already verified",
                    'username': username
                }
                return render(request, 'verify_email.html', context)
        except UserProfile.DoesNotExist:
                context = {
                    'message': "Invalid token or email already verified",
                    'username': username
                }
                return render(request, 'verify_email.html', context)

    else:
        username_pom = request.session.get('username_pom')
        if username_pom is not None:
            user = get_object_or_404(User, username=username)
            user_profile = get_object_or_404(UserProfile, user=user)
            # Generate verification token
            verification_token = user_profile.generate_verification_token()
            user_profile.verification_token = verification_token
            user_profile.save()
            if not user_profile.email_verified or not user_profile.is_verification_token_valid():
                # SEND VERIFICATION TOKEN
                MailSender.send_email_for_verification(request, user_profile.email, verification_token)
                return render(request, 'verify_email.html', {'username': username})
        return redirect("home")





