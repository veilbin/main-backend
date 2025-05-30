from rest_framework import serializers
from .models import File

# file serializer
class FileSeriailizer(serializers.ModelSerializer):
    share_token = serializers.CharField(max_length=200, required=False)
    share_link = serializers.CharField(max_length=600, required=False)
    
    class Meta:
        model = File
        fields = ['id','filename', 'file', 'owner', 'is_shareable', 'share_token', 'share_link', 'uploaded_at', 'expiration']
        read_only_fields = ['uploaded_at', 'share_token', 'share_link']

    