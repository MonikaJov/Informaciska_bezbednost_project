from django.conf import settings
from django.shortcuts import render
from django.core.mail import EmailMessage, get_connection


class MailSender:
    def send_email_for_verification(request, email, token):
        # this is used in the register method and verify_email method
        if '/verify_email/' in request.path or '/register' in request.path:
            with get_connection(
                    host=settings.EMAIL_HOST,
                    port=settings.EMAIL_PORT,
                    username=settings.EMAIL_HOST_USER,
                    password=settings.EMAIL_HOST_PASSWORD,
                    use_tls=settings.EMAIL_USE_TLS
            ) as connection:
                email_from = settings.EMAIL_HOST_USER
                subject = 'Verify your email'
                recipient_list = [email]
                message = 'Your verification code is: '+ str(token) + \
                          ".\nTo keep your account secure, don't share it with anyone."
                EmailMessage(subject, message, email_from, recipient_list, connection=connection).send()
                return render(request, 'home.html')
        # this is used in the two_factor_authentication method
        else:
            with get_connection(
                    host=settings.EMAIL_HOST,
                    port=settings.EMAIL_PORT,
                    username=settings.EMAIL_HOST_USER,
                    password=settings.EMAIL_HOST_PASSWORD,
                    use_tls=settings.EMAIL_USE_TLS
            ) as connection:
                email_from = settings.EMAIL_HOST_USER
                subject = 'One-time verification code'
                recipient_list = [email]
                message = 'Your verification code is: ' + str(token) + \
                          ".\nUse this one-time code to continue logging into your account."
                EmailMessage(subject, message, email_from, recipient_list, connection=connection).send()


