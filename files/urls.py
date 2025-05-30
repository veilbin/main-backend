from django.urls import path 
from django.conf import settings
from django.conf.urls.static import static
from .views import FileView, FileDetailView, FileShareView

urlpatterns = [
    path('files/', FileView.as_view(), name='files'),
    path('files/<int:id>/', FileDetailView.as_view(), name="file-details"),
    path('share/<uuid:share_token>/', FileShareView.as_view(), name='file-share')
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)