from re import template

from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from celery import shared_task
import logging

logger =  logging.getLogger('authentication')

# create function to send sign up email
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_signup_email(self, url, recipient_list) -> None: # send login notification email
    subject = "Email Subject"
    context = {"url": url}
    email_body = render_to_string('emails/email_template.html', context)
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )

# create function to send email verification mail
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_email_verification_email(self, url, recipient_list) -> None: # send login notification email
    subject = "Email Subject"
    context = {"url": url}
    email_body = render_to_string('emails/email_template.html', context)
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )


# send account reactivation email 
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_account_reactivation_email(self, url, recipient_list) -> None: 
    subject = "Email Subject"
    context = {"url": url}
    email_body = render_to_string('emails/email_template.html', context)
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )


# create function to send account re-activation success email
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_account_reactivation_success_email(self, recipient_list) -> None: 
    subject = "Email subject"
    # Render email template with dynamic data
    email_body = render_to_string('emails/email_template.html')
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )



# create function to send login email
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_login_email(self, recipient_list) -> None: # send login notification email
    subject = "Email Subject"
    email_body = render_to_string('emails/email_template.html')
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )


# create function to send password reset email
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_password_reset_email(self, url, recipient_list) -> None:
    subject = "Email Subject"
    context = {"url": url}
    email_body = render_to_string('emails/email_template.html', context)
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )


# create function to send password reset success email
@shared_task(bind=True, retry_backoffs=5, max_retries=3)
def send_password_reset_success_email(self, recipient_list) -> None:
    subject = "Email Subject"
    email_body = render_to_string('emails/email_template.html')
    # send the email
    send_mail(
        subject=subject,
        message= '',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=recipient_list,
        html_message=email_body,
    )