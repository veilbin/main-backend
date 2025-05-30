import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()

# file model 
class File(models.Model):
    filename = models.CharField(max_length=150, null=False, blank=False)
    file = models.FileField(upload_to="files/")
    is_shareable = models.BooleanField(default=True)
    share_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    share_link = models.URLField(max_length=600, blank=True, null=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    expiration = models.DateTimeField(null=False, blank=False)

    def save(self, *args, **kwargs):
        # generate share link if file is shareable 
        if self.is_shareable:
            base_url = "http://locachost:8080"
            self.share_link = f"{base_url}{reverse('file-share', kwargs={'share_token':str(self.share_token)})}"
        else:
            self.share_link = None 

        super().save(*args, **kwargs)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.filename}-{self.share_token}"


