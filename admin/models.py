from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


# accounts sechduled for deletion 
class DeletionSchedule(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    request_date = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user}"
    
    
