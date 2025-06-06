from django.contrib import admin
from .models import File

# file admin 
class FileAdmin(admin.ModelAdmin):
    list_display = ['filename', 'is_shareable', 'share_token', 'owner', 'uploaded_at', 'expiration']
    list_display_links = ['filename','is_shareable', 'owner']
    list_filter = ['is_shareable']
    search_fields = ['filename', 'owner']
    ordering = ['-expiration']
