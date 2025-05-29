from rest_framework import serializers

from .models import File

# file serializer
class FileSeriailizer(serializers.ModelSerializer):
    owner = serializers.CharField(required=False)
    filename = serializers.CharField(required=True, max_lenght=150)
    file = serializers.FileField(required=True)
    expiration = serializers.DateTimeField(required=True)
    
    class Meta:
        model = File
        fields = ['id','filename', 'file', 'owner', 'uploaded_at', 'expiration']
