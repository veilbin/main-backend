from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

# profile model 
class Profile(models.Model):
    fullname = models.CharField(max_length=80, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='profile')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    def __str__(self):
        return self.user.email
    
    class Meta:
        ordering = ['-created_at']
 

# accounts sechduled for deletion 
class DeletionSchedule(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='deletion_schedule')
    request_date = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(default=False)

    def __str__(self):
        return self.user.email