from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin



# create custom user model 
class CustomUserManager(BaseUserManager):
    
    def create_user(self, email, password=None, **extra_fields):
        if email is None:
            raise ValueError("Email is required")
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self.db)

        return user 
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(email, password, **extra_fields)

# user model 
class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=80, null=False, blank=False, unique=True)
    email_verification_token = models.CharField(max_length=255, null=True, blank=True)
    email_verification_token_created_at = models.DateTimeField(null=True, blank=True)
    email_is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_disabled = models.BooleanField(default=False)
    disabled_at = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_premium_user = models.BooleanField(default=False)
    premium_type = models.CharField(max_length=50, null=True, blank=True)
    login_trials = models.IntegerField(default=0)
    last_login = models.DateTimeField(null=True, blank=True)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    reactivation_token = models.CharField(max_length=15, null=True, blank=True)
    reactivation_token_created_at = models.DateTimeField(null=True, blank=True)
    last_account_reactivation = models.DateTimeField(null=True, blank=True)
    password_reset_token = models.CharField(max_length=255, null=True, blank=True)
    password_reset_token_created_at = models.DateTimeField(null=True, blank=True)
    last_password_reset = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'

    objects = CustomUserManager()

    # function to increment login trials
    def increment_login_trials(self):
        self.login_trials += 1
        self.last_failed_login = timezone.now()
        self.save()

    # function to reset login trials
    def reset_login_trials(self):
        self.login_trials = 0
        self.last_login = timezone.now()
        self.save()

    def __str__(self):
        return self.email

    class Meta:
        ordering = ['-created_at']
        # verbose_name = 'CustomUser'
        # verbose_name_plural = 'CustomUsers'
    