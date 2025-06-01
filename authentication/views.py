from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction
from django.utils import timezone
from datetime import timedelta, time
import logging
import secrets

from admin.models import DeletionSchedule
from util.api_response import ResponseUtils
from .serializers import (
    SignupSerializer,
    SigninSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    EmailActivationSerializer,
    ResetPasswordSerializer,
    ChangeEmailSerializer,
    AccountReactivationSerializer,
    EmailActivationRequestSerializer,
)
from .tasks import (
    send_signup_email, send_login_email,
    send_account_reactivation_email,
    send_password_reset_email,
    send_email_verification_email,
    send_password_reset_success_email,
    send_account_reactivation_success_email,
)

# define user
User = get_user_model()
# initiate logger
logger = logging.getLogger('authentication')

# create registration view
class SignupView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = SignupSerializer

    # function to handle POST request
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.create(
                    email = email
                )
                user.set_password(serializer.validated_data['password'])
                token = secrets.token_urlsafe(32)
                # save user model together with token
                with transaction.atomic():
                    user.email_verification_token = token
                    user.email_verification_token_created_at = timezone.now()
                    user.save(update_fields=["email_verification_token", "email_verification_token_created_at"])
                # send signup email
                send_signup_email.delay(
                    url= request.build_absolute_uri(f"/api/auth/verify_email/{token}/"),
                    recipient_list=[email,]
                )

                logger.info(f": New user account created for {email}")
                return ResponseUtils.success_response(
                    message="Account created successfully",
                    status_code=status.HTTP_201_CREATED
                )
            except Exception as e:
                logger.error(f": An error occurred while creating new user account: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Try again later.",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        # return error if serializer is invalid
        return ResponseUtils.error_response(
            message= "Incorrect data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )


# create Login view
class SigninView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = SigninSerializer

    # function to handle POST request
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            # authenticate the user
            user = authenticate(request, email=email, password=password)
            if user is not None:
                if not user.is_disabled and not user.is_locked:
                    # generate access and refresh token for user
                    refresh_token = RefreshToken.for_user(user)
                    # reset login trials
                    user.reset_login_trials()
                    logger.info(f": user {email} logged in successfully.")
                    # send login notification mail
                    send_login_email.delay(recipient_list=[email, ])
                    # return success response
                    return Response({
                        'result':'success',
                        'message': 'Login Successful',
                        'access_token': str(refresh_token.access_token),
                        'refresh_token': str(refresh_token),
                    }, status = status.HTTP_200_OK)
                if user.is_disabled:
                    try:
                        token = secrets.token_urlsafe(32)
                        with transaction.atomic():
                            # update user model with generated token
                            user.reactivation_token = token
                            user.reactivation_token_created_at = timezone.now()
                            user.save(update_fields=["reactivation_token", "reactivation_token_created_at"])

                        # send reactivation email
                        send_account_reactivation_email.delay(
                            url= request.build_absolute_uri(f"/api/auth/account_reactivation/{token}/"),
                            recipient_list=[email,]
                        )
                        # return response to user
                        return ResponseUtils.error_response(
                            message= "Your account is disabled. You'll receive an email shortly on how to re-activate your account.",
                            status_code= status.HTTP_403_FORBIDDEN
                        )
                    except Exception as e:
                        # log error
                        logger.error(f": An unexpected error occurred while generating and saving activation code for {email}: {e}", exc_info=True)
                        return ResponseUtils.error_response(
                            message= "An unexpected error occurred. Please try again later.",
                            status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                if user.is_locked:
                    # log activity
                    logger.warning(f": User {email} tried accessing a locked account", exc_info=True)
                    # return response to user
                    return ResponseUtils.error_response(
                        message= "Your account is locked. Please contact support.",
                        status_code= status.HTTP_403_FORBIDDEN
                    )
            else:
                # check if the provided email exist
                user_account = User.objects.filter(email__iexact=email).first()
                if user_account:
                    # define variable to use as measure for last failed login
                    time_since_last_failed_login = timedelta(hours=0)
                    # check the last failed login attempt of the user
                    if user_account.last_failed_login is None or user_account.last_failed_login == time(0,0,0) and user_account.login_trials < 5:
                        try:
                            # start atomic transaction to update fields
                            with transaction.atomic():
                                user_account.login_trials += 1
                                user_account.last_failed_login = timezone.now()
                                user_account.save(update_fields=["login_trials", "last_failed_login"])

                            return ResponseUtils.error_response(
                                message= "Incorrect account credentials.",
                                status_code= status.HTTP_401_UNAUTHORIZED
                            )
                        except Exception as e:
                            # log error
                            logger.error(f": An unexpected error occurred during atomic transaction on user_account: {e}", exc_info=True)
                            return ResponseUtils.error_response(
                                message= "An unexpected error occurred. Please try again later.",
                                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                            )
                    else:
                        time_since_last_failed_login = timezone.now() - user_account.last_failed_login
                        # check the user login trials
                        if user_account.login_trials >= 5:
                            # compare time since last failed login to minimum login trial time
                            if time_since_last_failed_login >= timedelta(hours=24):
                                try:
                                    with transaction.atomic():
                                        # set login trials to 1 and update last failed login
                                        user_account.login_trials = 1
                                        user_account.last_failed_login = timezone.now()
                                        user_account.save(update_fields=["login_trials", "last_failed_login"])

                                    return ResponseUtils.error_response(
                                        message= "Incorrect account credentials.",
                                        status_code= status.HTTP_401_UNAUTHORIZED
                                    )
                                except Exception as e:
                                    # log error
                                    logger.error(
                                        f": An unexpected error occurred during atomic transaction on user_account: {e}",
                                        exc_info=True)
                                    return ResponseUtils.error_response(
                                        message="An unexpected error occurred. Please try again later.",
                                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                                    )
                            else:
                                time_left = timedelta(hours=24) - time_since_last_failed_login
                                try:
                                    # lock user account and update last failed login
                                    with transaction.atomic():
                                        user_account.last_failed_login = timezone.now()
                                        user_account.save(update_fields=["last_failed_login"])
                                    # return error response
                                    return ResponseUtils.error_response(
                                        message= f" Your account is temporarily locked for {time_left} due to too many failed login attempts.",
                                        status_code= status.HTTP_403_FORBIDDEN
                                    )
                                except Exception as e:
                                    logger.error(f": An unexpected error occurred while locking and updating user {user_account.email} account due to too many failed login attempt: {e}", exc_info=True)
                                    return ResponseUtils.error_response(
                                        message= "An unexpected error occurred. Please try again later.",
                                        status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                                    )
                        else:
                            try:
                                # increment login trials and update last failed login
                                with transaction.atomic():
                                    user_account.login_trials += 1
                                    user_account.last_failed_login = timezone.now()
                                    user_account.save(update_fields=["login_trials", "last_failed_login"])

                                return ResponseUtils.error_response(
                                    message="Incorrect account credentials.",
                                    status_code=status.HTTP_401_UNAUTHORIZED
                                )
                            except Exception as e:
                                # log error
                                logger.error(
                                    f": An unexpected error occurred during atomic transaction on user_account: {e}",
                                    exc_info=True)
                                return ResponseUtils.error_response(
                                    message="An unexpected error occurred. Please try again later.",
                                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                                )
                else:
                    return ResponseUtils.error_response(
                        message= "Incorrect login credentials.",
                        status_code= status.HTTP_401_UNAUTHORIZED
                    )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )


# create logout view
class SignoutView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    # function to handle POST request
    def post(self, request, *args, **kwargs):
        # extract token from authorization header
        token = self.get_bearer_token(request.headers.get('Authorization'))
        if not token:
            # log warning
            logger.warning(": A logout attempt without a bearer token was made", exc_info=True)
            return ResponseUtils.error_response(
                message="Authorization header must contain a valid bearer token",
                status_code= status.HTTP_403_FORBIDDEN
            )
        # try to blacklist token
        try:
            logout_token = RefreshToken(token)
            logout_token.blacklist()
            return ResponseUtils.success_response(
                message= "Logout successful",
                status_code= status.HTTP_204_NO_CONTENT
            )
        except ValidationError:
            return ResponseUtils.error_response(
                message= "Token provided is invalid",
                status_code= status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # log error
            logger.error(f": An unexpected error occurred while blacklisting token: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred. Please try again later",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    # create function to get bearer token
    def get_bearer_token(self, authorization_header):
        # extract and validate the bearer token from authorization header
        if not authorization_header:
            return None
        parts = authorization_header.split()
        if len(parts) == 2 and parts[0].lower == 'bearer':
            return parts[1]
        return  None


# create change password view
class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated, ]
    serializer_class = ChangePasswordSerializer

    # function to handle POST request
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        if serializer.is_valid():
            try:
                new_password = serializer.validated_data['new_password']
                user = request.user
                with transaction.atomic():
                    user.set_password(new_password)
                    user.last_password_reset = timezone.now()
                    user.save(update_fields=["password", "last_password_reset"])
                # send email
                send_password_reset_success_email(recipient_list=[user.email, ])
                logger.info(f": user {user.email} password was changed by {user}")
                return ResponseUtils.success_response(
                    message="Password changed successfully.",
                    status_code= status.HTTP_200_OK
                )
            except  Exception as e:
                logger.error(f": An unexpected error occurred while changing user {user.email} password: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )

# create user forgot password view
class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = ForgotPasswordSerializer

    # function to handle POST request
    def post(self, request, *args, **kwarg):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email__iexact=email)
            
            try:
                # generate secret token
                token = secrets.token_urlsafe(32)
                # save token to user model
                with transaction.atomic():
                    user.password_reset_token = token
                    user.password_reset_token_created_at = timezone.now()
                    user.save(update_fields=["password_reset_token", "password_reset_token_created_at"])
                # send email to user
                send_password_reset_email.delay(
                    url= request.build_absolute_uri(f"/api/auth/reset_password/{token}/"),
                    recipient_list=[email,]
                )
                return ResponseUtils.success_response(
                    message= "Password reset link has been sent to your email.",
                    status_code= status.HTTP_200_OK
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while requesting reset password link: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )


# create reset password view
class ResetPasswordView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = ResetPasswordSerializer

    # function to handle POST request
    def post(self, request, token, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['password_reset_token']
            password = serializer.validated_data['new_password']
            user = User.objects.filter(password_reset_token__iexact=token).first()
            email = user.email 
            try:
                if user:
                    if user.password_reset_token == token:
                        if (timezone.now() - user.password_reset_token_created_at) >= timedelta(minutes=30):
                            # log warning
                            logger.warning(f": User {email} tried resetting password with an expired link", exc_info=True)
                            return ResponseUtils.error_response(
                                message= "Expired password reset link. Please request a new link.",
                                status_code= status.HTTP_403_FORBIDDEN
                            )
                        else:
                            with transaction.atomic():
                                # update user password
                                user.set_password(password)
                                user.password_reset_token = None
                                user.password_reset_token_created_at = None
                                user.last_password_reset = timezone.now()
                                user.save(update_fields=["password", "password_reset_token", "password_reset_token_created_at", "last_password_reset"])
                            # send email
                            send_password_reset_success_email.delay(recipient_list=[email, ])
                            logger.info(f": Password reset for {email} was successfully done by {request.user}")
                            # logout the user by blacklisting all the user's token
                            self.blacklist_user_tokens(user)
                            return ResponseUtils.success_response(
                                message="Password reset successful.",
                                status_code=status.HTTP_200_OK
                            )
                    else:
                        return ResponseUtils.error_response(
                            message= "Incorrect password reset link. Please request a new link.",
                            status_code= status.HTTP_400_BAD_REQUEST
                        )
                return ResponseUtils.error_response(
                    message= "User account not found",
                    status_code= status.HTTP_403_FORBIDDEN
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while resetting user {email} password: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )

    # create function to blacklist user token
    def blacklist_user_tokens(self, user):
        try:
            # retrieve all user's outstanding tokens
            tokens = OutstandingToken.objects.filter(user=user)
            # blacklist tokens
            for token in tokens:
                token.blacklisted = True
                token.save()
        except Exception as e:
            logger.error(f": An unexpected error occurred while blacklisting user token after password reset: {e}",
                         exc_info=True)
            raise AuthenticationFailed("Failed to logout user from older devices")

# email verification view
class EmailVerificationView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = EmailActivationSerializer

    # function to handle POST request
    def post(self, request, token, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['email_activation_token']
            user = User.objects.filter(email_verification_token__iexact=token).first()
            email = user.email
            try:
                if user:
                    if user.email_verification_token == token:
                        if (timezone.now() - user.email_verification_token_created_at) >= timedelta(minutes=30):
                            # log warning
                            logger.warning(f": User {email} tried verifying email with an expired link", exc_info=True)
                            return ResponseUtils.error_response(
                                message= "Expired email verification link. Please request a new link.",
                                status_code= status.HTTP_403_FORBIDDEN
                            )
                        else:
                            with transaction.atomic():
                                # update user model
                                user.email_is_verified = True
                                user.email_verification_token = None
                                user.email_verification_token_created_at = None
                                user.save(update_fields=["email_is_verified", "email_verification_token", "email_verification_token_created_at"])
                            logger.info(f": {email} email was successfully verified")
                            return ResponseUtils.success_response(
                                message="Email verification successful.",
                                status_code=status.HTTP_200_OK
                            )
                    else:
                        return ResponseUtils.error_response(
                            message= "Incorrect email verification link. Please request a new link.",
                            status_code= status.HTTP_400_BAD_REQUEST
                        )
                return ResponseUtils.error_response(
                    message= "User account not found",
                    status_code= status.HTTP_403_FORBIDDEN
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while verifiying email of {email}: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )
    

    
# account reactivation view
class AccountReactivationView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = AccountReactivationSerializer

    # function to handle POST request
    def post(self, request, token, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['account_reactivation_token']
            user = User.objects.filter(account_reactivation_token__iexact=token).first()
            email = user.email
            try:
                if user:
                    if user.reactivation_token == token:
                        if (timezone.now() - user.reactivation_token_created_at) >= timedelta(minutes=30):
                            # log warning
                            logger.warning(f": User {email} tried reactivationg account with an expired link", exc_info=True)
                            return ResponseUtils.error_response(
                                message= "Expired account reactivation link. Please request a new link.",
                                status_code= status.HTTP_403_FORBIDDEN
                            )
                        else:
                            with transaction.atomic():
                                # update user model
                                user.is_disabled = False
                                user.is_active = True
                                user.reactivation_token = None
                                user.reactivation_token_created_at = None
                                user.save(update_fields=["is_disabled", "is_active", "reactivation_token", "reactivation_token_created_at"])
                            logger.info(f": {email} account was successfully reactivated")
                            send_account_reactivation_success_email.delay(recipient_list=[email,])
                            return ResponseUtils.success_response(
                                message="Account reactivation successful.",
                                status_code=status.HTTP_200_OK
                            )
                    else:
                        return ResponseUtils.error_response(
                            message= "Incorrect account reactivation link. Please request a new link.",
                            status_code= status.HTTP_400_BAD_REQUEST
                        )
                return ResponseUtils.error_response(
                    message= "User account not found",
                    status_code= status.HTTP_403_FORBIDDEN
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while verifiying email of {email}: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )
    
# change email 
class ChangeEmailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangeEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.data)
        user = request.user

        if serializer.is_valid():
            try:
                new_email = serializer.validated_data['new_email']
                user.email = new_email
                user.save()
                
                # send email to user 

                return ResponseUtils.success_response(
                    message= "Email changed successfully",
                    status_code= status.HTTP_200_OK
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while updating email of {user.email}: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )

# email verification link request 
class EmailActivationRequestView(APIView):
    permission_classes = [permissions.AllowAny, ]
    serializer_class = EmailActivationRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email__iexact=email).first()
        if serializer.is_valid():
            try:
                # generate secret token
                token = secrets.token_urlsafe(32)
                # save token to user model
                with transaction.atomic():
                    user.email_verification_token = token
                    user.email_verification_token_created_at = timezone.now()
                    user.save(update_fields=["email_verification_token", "email_verification_token_created_at"])
                # send email to user
                send_password_reset_email.delay(
                    url= request.build_absolute_uri(f"/api/auth/verify_email/{token}/"),
                    recipient_list=[email,]
                )
                return ResponseUtils.success_response(
                    message= "A new verification link has been sent to your email.",
                    status_code= status.HTTP_200_OK
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while requesting email verification link: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )
    

# account reactivation link request 
class AccountReactivationRequestView(APIView):
    permission_classes = [permissions.AllowAny, ]
    serializer_class = EmailActivationRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email__iexact=email).first()
        if serializer.is_valid():
            try:
                # generate secret token
                token = secrets.token_urlsafe(32)
                # save token to user model
                with transaction.atomic():
                    user.reactivation_token = token
                    user.reactivation_token_created_at = timezone.now()
                    user.save(update_fields=["reactivation_token", "reactivation_token_created_at"])
                # send email to user
                send_email_verification_email.delay(
                    url= request.build_absolute_uri(f"/api/auth/account_reactivation/{token}/"),
                    recipient_list=[email,]
                )
                return ResponseUtils.success_response(
                    message= "A new activation link has been sent to your email.",
                    status_code= status.HTTP_200_OK
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while requesting account reactivation link: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )
    

# password reset link request 
class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny, ]
    serializer_class = EmailActivationRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email__iexact=email).first()
        if serializer.is_valid():
            try:
                # generate secret token
                token = secrets.token_urlsafe(32)
                # save token to user model
                with transaction.atomic():
                    user.password_reset_token = token
                    user.password_reset_token_created_at = timezone.now()
                    user.save(update_fields=["password_reset_token", "password_reset_token_created_at"])
                # send email to user
                send_password_reset_email.delay(
                    url= request.build_absolute_uri(f"/api/auth/password_reset/{token}/"),
                    recipient_list=[email,]
                )
                return ResponseUtils.success_response(
                    message= "A new reset link has been sent to your email.",
                    status_code= status.HTTP_200_OK
                )
            except Exception as e:
                # log error
                logger.error(f": An unexpected error occurred while requesting password reset link: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred. Please try again later.",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return ResponseUtils.error_response(
            message= "Invalid data format.",
            details= serializer.errors,
            status_code= status.HTTP_400_BAD_REQUEST
        )
    
    
# account disablement request 
class DisableAccountView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def post(self, request, *args, **kwargs):
        user = self.request.user 
        try:
            with transaction.atomic():
                user.is_disabled = True
                user.disabled_at = timezone.Now()
                user.save(update_fields=["is_disabled", "is_disabled_at"])

            # blacklist user token 
            
            # add user to to be deleted model 
            to_be_deleted = DeletionSchedule.objects.create(user=user)
            to_be_deleted.save()

            return ResponseUtils.success_response(
                message= "Account diabled successfully",
                status_code= status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f": Error disabling user account: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        