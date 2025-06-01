from django.contrib.auth import get_user_model
from rest_framework import serializers
import re

User = get_user_model()

# create user registration serializer
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True)
    password_again = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_again']

    # validate email
    def validate_email(self, value: str) -> str:
        # create dictionary to store all errors
        errors = {}

        # check email value
        if not value or value.isspace():
            errors["email"] = "Email is required"
        # check email length
        if len(value) < 6 or len(value) > 80:
            errors["email"] = "Invalid email length. Email should be at least 6 characters, and not more than 150 characters"
        # check if email already exist
        if User.objects.filter(email__iexact=value).exists():
            errors["email"] = f"Email {value} is unavailable"
        # check for errors
        if errors:
            raise serializers.ValidationError(errors)
        return value

    # validate password
    def validate(self, data) -> str:
        # create dictionary to record errors
        errors = {}
        # get values from data
        password = data.get('password')
        password_again = data.get('password_again')

        # check if password contain whitespace
        if not password or password.isspace():
            errors["password"] = "Password is required"
        # check password length
        if len(password) < 8 or len(password) > 128:
            errors["password"] = "Password must be between 8 and 128 characters"
        # check password for special characters
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors["password"] = "Password must contain at least one special character"
        # check for digit
        if not any(p.isdigit() for p in password):
            errors["password"] = "Password must contain at least one digit"
        # check password for lowercase
        if not any(p.islower() for p in password):
            errors["password"] = "Password must contain at least one lowercase"
        # check password for uppercase
        if not any(p.isupper() for p in password):
            errors["password"] = "Password must contain at least one uppercase"
        # check if both passwords match
        if password_again != password:
            errors["password"] = "Passwords do not match"
        # check for errors
        if errors:
            raise  serializers.ValidationError(errors)
        return data
    
# login serializer
class SigninSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=60, min_length=6)
    password = serializers.CharField(required=True, min_length=8)


# change password serializer
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password_again = serializers.CharField(required=True)

    # validate data
    def validate(self, data):
        errors = {}

        old_password = data.get('old_password')
        new_password = data.get('new_password')
        new_password_again = data.get('new_password_again')

        # get user from context
        user = self.context['request'].user
        # check if provided password is valid
        if not user.check_password(old_password):
            errors['password'] = "Old password is incorrect"

        # validate new password
        if not new_password or new_password.isspace():
            errors['password'] = "New password is required"
        # check if old and new password are the same
        if user.check_password(old_password) and new_password == old_password:
            errors['password'] = "You cannot use the same password as your old password"
        if len(new_password) < 8:
            errors["password"] = "Password must be at least 8 characters"
        # check password for special characters
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
            errors["password"] = "Password must contain at least one special character"
        # check for digit
        if not any(p.isdigit() for p in new_password):
            errors["password"] = "Password must contain at least one digit"
        # check password for lowercase
        if not any(p.islower() for p in new_password):
            errors["password"] = "Password must contain at least one lowercase"
        # check password for uppercase
        if not any(p.isupper() for p in new_password):
            errors["password"] = "Password must contain at least one uppercase"
        # check if both passwords match
        if new_password_again != new_password:
            errors["password"] = "Both fields for new password must match"
        # check for errors
        if errors:
            raise  serializers.ValidationError(errors)
        return data



# forgot password serializer
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=60, min_length=6)

    # validate email
    def validate_email(self, value):
        # create error dict
        errors = {}

        # check email value
        if not value or value.isspace():
            errors["email"] = "Please provide a valid email"
        if len(value) < 6 or len(value) > 60:
            errors["email"] = "Email can only be between 6 to 60 characters"
        # check if provided email exists
        if not User.objects.filter(email__iexact=value).exists():
            errors["email"] = f"Can't find account with email {value}"
        if errors:
            raise serializers.ValidationError(errors)

        return value


# reset password serializer
class ResetPasswordSerializer(serializers.Serializer):
    password_reset_token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password_again = serializers.CharField(required=True)

    # validate data
    def validate(self, data):
        errors = {}
        # get values from data
        token = data.get(token)
        new_password = data.get('new_password')
        new_password_again = data.get('new_password_again')

        # check if token is not empty 
        if not token or token.isspace():
            errors['token'] = "Please provide a valid token"
        # validate new password
        if not new_password or new_password.isspace():
            errors['password'] = "New password is required"
        if len(new_password) < 8:
            errors["password"] = "Password must be at least 8 characters"
        # check password for special characters
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
            errors["password"] = "Password must contain at least one special character"
        # check for digit
        if not any(p.isdigit() for p in new_password):
            errors["password"] = "Password must contain at least one digit"
        # check password for lowercase
        if not any(p.islower() for p in new_password):
            errors["password"] = "Password must contain at least one lowercase"
        # check password for uppercase
        if not any(p.isupper() for p in new_password):
            errors["password"] = "Password must contain at least one uppercase"
        # check if both passwords match
        if new_password_again != new_password:
            errors["password"] = "New passwords must match"
        # check for errors
        if errors:
            raise serializers.ValidationError(errors)
        return data



# email activation serializers
class EmailActivationSerializer(serializers.Serializer):
    email_activation_token = serializers.CharField(required=True)

# account reactivation serializer
class AccountReactivationSerializer(serializers.Serializer):
    account_reactivation_token = serializers.CharField(required=True)

# change email serializer 
class ChangeEmailSerializer(serializers.ModelSerializer):
    new_email = serializers.EmailField(max_length=80, required=True)

    class Meta:
        model = User 
        fields = ['email']

    # validate email 
    def validate_email(self, value: str) -> str:
        # create dictionary to store all errors
        errors = {}
        user = self.context['request'].user

        # check email value
        if not value or value.isspace():
            errors["email"] = "Email is required"
        # check email length
        if len(value) < 6 or len(value) > 80:
            errors["email"] = "Invalid email length. Email should be at least 6 characters, and not more than 150 characters"
        # check if email already exist
        if value != user.email and User.objects.filter(email__iexact=value).exists():
            errors["email"] = f"Email {value} is unavailable"
        # check for errors
        if errors:
            raise serializers.ValidationError(errors)
        return value
    
# new link request serializer 
class EmailActivationRequestSeriaizer(serializers.Serializer):
    email = serializers.EmailField(required=True)


# user serializer 
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        