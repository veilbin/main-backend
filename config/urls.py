from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include

urlpatterns = [ 
    path('admin/', admin.site.urls),
    path('api/files/', include('files.urls')),
    path('api/auth/', include('authentication.urls')),
    path('api/users/', include('users.urls')),
    # path('api/auth/staff/admin/', include('veilbin_staff.urls')),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)