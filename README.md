# Informaciska_bezbednost_proekt

This project is a Django web application that includes features for user registration, login, and a basic home page. As a database to store user profiles, I’m using Django database. 

The models.py file is a crucial component of the application, defining the data models used by the Django ORM (Object-Relational Mapping). These models represent the structure of the database tables and the relationships between them. 

The views.py file contains the Django views that handle the logic for processing user requests and rendering appropriate responses. Views are responsible for interacting with the models to fetch or update data and rendering the appropriate templates.

The settings.py file contains configuration settings for the Django project. These settings control different aspects of the project, including database configuration, authentication and more.

The admin.py file is used to configure and customize the behavior of the Django admin interface.

The urls.py file defines the URL patterns for the Django project. It maps URLs to corresponding views, allowing the application to respond to different requests. 

## Installation and starting the project
Installation Before running the project, ensure you have the following prerequisites:
Python 3.8 or higher installed Django 3.2 or higher installed To set up the project, follow these steps:
1.Clone the project repository from GitHub: https://github.com/MonikaJov/Informaciska_bezbednost_project

2.Open the file as PyCharm project

3.Type in terminal: cd IB_proekt

4.To run the project type the following command in terminal: python manage.py runserver

5.Open your web browser and visit http://localhost:8000/login to access the login page.

*To be able to access the database at http://127.0.0.1:8000/admin/ you need to log in as admin - username:admin password:admin

*To be able to send emails make sure to add your own email and password in setting.py because I'm not sharing my password for security reasons. If you're using your google account, make sure to generate an app password and use that password otherwise email sending wont work.

Technologies used: Python, HTML, CSS, Bootstrap, JavaScript, Django.

# Homework 2 documentation:

## User registration:

### register method:

The register method in views.py renderes the 'register.html' and at http://127.0.0.1:8000/register/ the user is presented with a registration form.
When request = ‘POST’ ie when user fills the form at http://127.0.0.1:8000/register/ the register method in views.py handles user registration in the web application. It takes the necessary information provided by new users and performs various checks to ensure the integrity and security of user data. Some of the checks include:
-	Email validation using the validate_email method from django.core.validators
-	Checking if the email is already in use with UserProfile.objects.filter(email=email).exists()
-	Checking if the phone number is already in use similarly with UserProfile.objects.filter(phone_number=phone_number).exists()
-	Checking if the two passwords match (password and confirm password)
-	Password validation using validate_password method from django.contrib.auth.password_validation. The password is validated if it contains at least 1 digit, 3 special characters, 4 lowercase characters and 5 uppercase characters.
-	Phone number validation, since in models.py phone_number is PhoneNumberField(), when checking if form.is_valid(), it also checks if the phone number is valid.

When some of the integrity and security checks fails, the user is given a corresponding error message.


Password hashing is also performed on the password before it’s stored in the database using the hash_password method from class PasswordHasher that I created in password_hasher_with_salt.py. The hash_password method generates salt and hashes the password with the salt (bcrypt.hashpw(password, salt)). Even tho in Django manual password hashing is not necessary I'm doing this just to prove that I know how to keep passwords safe.


After all the necessary information is collected from the user trying to register, a verification token is generated and is sent to the user via email to confirm their email address. For sending email I created a class MailSender in mailsender.py and a method send_email_for_verification. In the send_email_for_verification method I’m establishing a connection with my gmail account and using it to send a mail containing the token to the email address that the user provided. Something worth mentioning here is that I made the verification token only be valid for one minute.
After all that is done, a user profile is created and 'verify_email.html' is rendered and the user goes to http://127.0.0.1:8000/verify_email/.
 
 
###  verify_email method:
The verify_email method in views.py is called when the user types the verification token and presses the button in http://127.0.0.1:8000/verify_email/. This method checks if the token that the user typed matches the token that was sent via email and if the token is valid. If they don’t match or token is not valid the user is given a corresponding error message, but if they do match and the token is valid then email is verified and user goes to http://127.0.0.1:8000/login/.

## User login:

### login_form method:
When request=’GET’, the called login_form method in views.py rederes 'login.html' and user goes to http://127.0.0.1:8000/login/
The login_form method in views.py is also called when the user types their username and password in http://127.0.0.1:8000/login/. In that case, request=’POST’ and several things are preformed:
-	Checks if a user profile exists with that username. When the check fails, the user is given a corresponding error message.
-	Checks if the password that the user types matched the password stored in the database. The password is hashed so password_hasher.check_password(password, user_profile.password) is used. The method check_password is from the class PasswordHasher that I created in password_hasher_with_salt.py. When the check fails, the user is given a corresponding error message.
-	Check if two factor authorisation is enabled for the user. If it is then user is redirected to http://127.0.0.1:8000/two_factor_authentication/. 
-	If not, then the person is authenticated, logged in and redirected to http://127.0.0.1:8000/posst. 

### two_factor_authentication method:
When request=’GET’, the called two_factor_authentication method in views.py generates a token and sends it via email to the user’s email address, similarly the way register method did. After that, ‘two_factor_authentication.html’ is rendered and user goes to http://127.0.0.1:8000/two_factor_authentication/.
The two_factor_authentication method in views.py is also called when the user types the token in http://127.0.0.1:8000/two_factor_authentication/. In that case, request=’POST’ and several things are preformed:
-	Check if the token that the user typed matches the token that was sent via email and if the token is valid. 
-	If they don’t match or token is not valid the user is given a corresponding error message, but if they do match and the token is valid then user is logged in user goes to http://127.0.0.1:8000/posts.

### home method:
The home method is called after the user has logged in. It checks if the user is logged in and if so, it retrieves all the blog posts from the BlogPost model and the UserProfile associated with the current user. Then ‘blog_list.html’ is rendered with the provided context and the user goes to http://127.0.0.1:8000/posts where a web page is presented that lists all blogs that users have posted. The web page also has a navigation bar that has a search field and a filter form that the user can use to search for a post with a specific title or content and filter posts by creation dates. 
 
# Homework 3 documentation:

## Defining and managing roles:

### class UserProfile in models.py:
In the UserProfile class I added a ‘role’ attribute that will define the role that the user profile has. It can have one of three values: ‘ADMIN’, ‘PREMIUM USER’ or ‘USER’, with default role ‘USER’.
The admin user is the only one for now that can assign roles to user profiles through the database.
 
## Access control:

•	To write blogs, the user needs to be a premium user or an admin. 

•	To change roles, the user needs to be an admin. 

•	Any user can comment on a post, but only the author can edit their post, and both authors and admins can delete a post. 

•	Comments can be deleted by the author of the comment, the author of the post or the page admin. 

To be able to do that I used a Django template code that uses conditional rendering based on the user's role ({% if user_profile.role == 'role_name' %} ).
  
## Additionally::
•	Users can also block other users so they wouldn’t be able to see their blogs.

•	User can view thir profile at http://127.0.0.1:8000/profile/.



