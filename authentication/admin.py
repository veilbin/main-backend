from django.contrib import admin
from .models import CustomUser

# create custom user admin class
class CustomUserAdmin(admin.ModelAdmin):
    model = CustomUser

    list_display = ['email', 'email_is_verified', 'is_active','is_disabled', 'last_login', 'updated_at', 'created_at', ]
    list_display_links = ['email','email_is_verified', 'is_active']
    list_filter = ['is_active', 'email_is_verified', 'is_disabled', 'is_locked', 'is_staff', 'is_superuser']
    fieldsets = [
        ('Basic Info', {'fields': ('email',)}),
        ('Permissions', {'fields': ('is_active', 'is_disabled',  'is_staff', 'is_locked', 'is_superuser',
                                    'email_is_verified', 'groups', 'user_permissions')}),
        ('Account Information', {'fields': ('last_login', 'last_failed_login', 'login_trials', 'reactivation_token', 'reactivation_token_created_at')})
    ]
    ordering = ['-email']
    search_fields = ['email']

admin.site.register(CustomUser, CustomUserAdmin)