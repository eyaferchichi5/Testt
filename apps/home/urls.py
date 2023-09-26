from django.urls import path, re_path
from apps.home import views
from apps.home.views import device_table, inventaire_table, sentinels_table, edit_profile

urlpatterns = [
    path('', views.index, name='index'),
    path('ad.html/', views.ad_model, name='ad_model'),

    path('page-404/', views.page_404, name='page_404'),
    path('page-500/', views.page_500, name='page_500'),
    #path('<str:path>/', views.pages, name='pages'),
    path('sophos.html/', views.computer_table, name='computer_table'),
    path('defender.html/', device_table, name='device_table'),
    path('askit.html/', views.inventaire_table, name='inventaire_table'),
    path('sentinels.html/', sentinels_table, name='sentinels_table'),
    path('upload.html/', views.upload_ad_file, name='upload_ad_file'),
    path('upload_computer.html/', views.upload_file_computer, name='upload_file_computer'),
    path('upload_inventaire.html/', views.upload_file_inventaire, name='upload_file_inventaire'),
    path('upload_device.html/', views.upload_file_device, name='upload_file_device'),
    path('upload_sentinels.html/', views.upload_file_sentinels, name='upload_file_sentinels'),
    path('ad/delete/<str:ad_nom>/', views.delete_ad, name='delete_ad'),
    path('ad_model/edit/<str:pk>/', views.edit_ad, name='edit_ad'),
    path('search_result.html/', views.search, name='search'),
    path('page-user.html/', edit_profile, name='edit_profile'),
    path('anomalie-sophos.html/', views.anomalie_sophos, name='anomalie_sophos'),
    path('conformity_check.html/', views.detect_anomalies_view, name='detect_anomalies_view'),
    path('verifierd/', views.verifier_doublons, name='verifier_doublons'),
    path('sap_table/', views.sap_table, name='sap_table'),
    path('upload_sap.html/', views.upload_file_sap, name='upload_file_sap'),
    path('verifiaction/', views.verifier_laskit_dans_sap, name='verifier_laskit_dans_sap'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('confirm_upload.html/', views.confirm_upload_ad, name='confirm_upload_ad'),

]
