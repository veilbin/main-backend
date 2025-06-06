from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import Profile, DeletionSchedule

User= get_user_model()

# profile serializer
class ProfileSerializer(serializers.ModelSerializer):
    fullname = serializers.CharField(max_length=80, required=True)
    user = serializers.CharField(required=False)

    class Meta:
        model = Profile
        fields = ['id', 'fullname', 'user', 'created_at', 'updated_at']

# deletion schedule 
class DeletionSerializer(serializers.ModelSerializer):
    user = serializers.CharField(required=False)

    class Meta:
        models = DeletionSchedule 
        feilds = ['id', 'user', 'request_date', 'approved'] 