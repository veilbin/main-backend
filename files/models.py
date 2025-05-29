from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

# file model 
class File(models.Model):
    filename = models.CharField(max_length=150, null=False, blank=False)
    file = models.FileField(upload_to="files/")
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    expiration = models.DateTimeField(null=False, blank=False)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.owner}-{self.filename}"

