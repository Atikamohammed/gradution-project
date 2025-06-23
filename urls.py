from django.urls import path
from . import views

urlpatterns = [
     path('', views.home, name='home'),
    path('admin-login/', views.admin_login, name='admin_login'),
    path('user-login/', views.user_login, name='user_login'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
     path('view-logs/', views.view_logs, name='view_logs'),
    path('admin-logout/', views.admin_logout, name='admin_logout'),
    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    path('view-logsuser/', views.view_logsuser, name='view_logsuser'),
     path('test-algorithm/', views.test_algorithm, name='test_algorithm'),



 path('add/', views.add_device, name='add_device'),
    path('monitor/', views.monitor_devices, name='monitor_devices'),
    path('logs/', views.view_logs, name='view_logs'),
    path('test_panel/', views.test_panel, name='test_panel'),
     path('simulate-attack/', views.simulate_attack, name='simulate_attack'),


]
