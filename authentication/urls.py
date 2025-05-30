from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

from .views import (
    UserRegistrationView, UserLoginView, UserLogoutView,
    UserAccountReactivation, UserChangePasswordView,
    UserEmailChange, UserForgotPasswordView,
    UserResetPasswordView, UserEmailVerification,
    EmailVerificationLinkRequest, AccountActivationLinkRequest,
    PasswordResetLinkRequest, DisableAccount
)

urlpatterns = [
    path('signup/', UserRegistrationView.as_view(), name="signup"),
    path('signin/', UserLoginView.as_view(), name="signin"),
    path('signout/', UserLogoutView.as_view(), name="signout"),
    path('account_reactivation/', UserAccountReactivation.as_view(), name="account_reactivation"),
    path('change_password/', UserChangePasswordView.as_view(), name="change_password"),
    path('change_email/', UserEmailChange.as_view(), name="change_email"),
    path('forgot_password/', UserForgotPasswordView.as_view(), name="forgot_password"),
    path('reset_password/', UserResetPasswordView.as_view(), name="reset_password"),
    path('email_verification/', UserEmailVerification.as_view(), name="email_verification"),
    path('email_verification_request/', EmailVerificationLinkRequest.as_view(), name="email_verification_request"),
    path('account_activation_request/', AccountActivationLinkRequest.as_view(), name="account_activation_request"),
    path('password_reset_request/', PasswordResetLinkRequest.as_view(), name="password_reset_request"),
    path('disabe_account/', DisableAccount.as_view(), name="disable_account")
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)