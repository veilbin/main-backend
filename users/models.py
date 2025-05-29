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
        return self.user
    
    class Meta:
        ordering = ['-created_at']
