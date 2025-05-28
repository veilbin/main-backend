from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
from django.dispatch import receiver
from users.models import Profile
import logging

logger = logging.getLogger("authentication")
User = get_user_model()

@receiver(post_save, sender=User)
def manage_user_profile(sender, instance, created, **kwargs):
    try:
        if created:
            # create a profile for new users
            Profile.objects.create(user=instance)
        else:
            # save the profile when the user is updated
            instance.profile.save()
    except Exception as e:
        logger.error(f": An unexpected error occurred in authentication signals, while trying to save user profile: {e}", exc_info=True)