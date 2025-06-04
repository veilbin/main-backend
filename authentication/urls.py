from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

from .views import (
    SignupView, SigninView, SignoutView,
    AccountReactivationView, ChangePasswordView,
    ChangeEmailView, ForgotPasswordView,
    ResetPasswordView, EmailVerificationView,
    EmailActivationRequestView, AccountReactivationRequestView,
    PasswordResetRequestView, DisableAccountView
) 

urlpatterns = [
    path('signup/', SignupView.as_view(), name="signup"),
    path('signin/', SigninView.as_view(), name="signin"),
    path('signout/', SignoutView.as_view(), name="signout"), 
    path('account_reactivation/', AccountReactivationView.as_view(), name="account_reactivation"),
    path('change_password/', ChangePasswordView.as_view(), name="change_password"),
    path('change_email/', ChangeEmailView.as_view(), name="change_email"),
    path('forgot_password/', ForgotPasswordView.as_view(), name="forgot_password"),
    path('reset_password/', ResetPasswordView.as_view(), name="reset_password"),
    path('verify_email/', EmailVerificationView.as_view(), name="verify_email"),
    path('email_verification_request/', EmailActivationRequestView.as_view(), name="email_verification_request"),
    path('account_activation_request/', AccountReactivationRequestView.as_view(), name="account_activation_request"),
    path('password_reset_request/', PasswordResetRequestView.as_view(), name="password_reset_request"),
    path('disabe_account/', DisableAccountView.as_view(), name="disable_account")
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)