import pandas as pd
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from .form import ADForm, UserProfileForm
from .form import UploadFileForm
from django.contrib import messages
from datetime import datetime, timedelta

from .models import Sophos, Askit, AD, Defender, Sentinels, SAP, UserProfile


@login_required(login_url="/login/")
def index(request):
    computers_count = Sophos.objects.count()
    inventory_ads_count = Askit.objects.count()
    devices_count = Defender.objects.count()
    ad_count = AD.objects.count()
    total_stock = Askit.objects.filter(statut='En stock').count()
    total_service = Askit.objects.filter(statut='En service').count()
    up_to_date_count = Sentinels.objects.filter(vulnerability_status='Up to date').count()
    requires_patching_count = Sentinels.objects.filter(vulnerability_status='Requires patching').count()
    updated_count = Defender.objects.filter(antivirus_status='Updated').count()
    not_updated_count = Defender.objects.filter(antivirus_status='Not updated').count()
    unknown_count = Defender.objects.filter(antivirus_status='Unknown').count()
    sentinels_count = Sentinels.objects.count()

    context = {
        'computers_value': computers_count,
        'inventory_ads_value': inventory_ads_count,
        'devices_value': devices_count,
        'ad_value': ad_count,
        'total_stock': total_stock,
        'total_service': total_service,
        'updated_count': updated_count,
        'not_updated_count': not_updated_count,
        'unknown_count': unknown_count,
        'up_to_date_count': up_to_date_count,
        'requires_patching_count': requires_patching_count,
        'sentinels_value': sentinels_count,

    }

    return render(request, 'home/index.html', context)


@login_required(login_url="/login/")
def computer_table(request):
    context = {'segment': 'computer_table'}
    query = request.GET.get('q')

    if query:
        computers = Sophos.objects.filter(name__icontains=query).values('health_status', 'name', 'ip', 'os',
                                                                          'protection', 'last_user', 'last_active',
                                                                          'computer_group', 'tamper_protection')
    else:
        computers = Sophos.objects.values('health_status', 'name', 'ip', 'os', 'protection', 'last_user',
                                            'last_active', 'computer_group', 'tamper_protection')

    paginator = Paginator(computers, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context['computers'] = page_obj
    context['query'] = query

    return render(request, 'home/sophos.html', context)


@login_required(login_url="/login/")
def device_table(request):
    context = {'segment': 'device_table'}
    query = request.GET.get('q')

    if query:
        devices = Defender.objects.filter(device_name__icontains=query).values('device_id', 'device_name', 'domain',
                                                                          'first_seen', 'last_device_update',
                                                                          'os_platform', 'os_distribution',
                                                                          'os_version', 'os_build',
                                                                          'windows_10_version', 'tags', 'group',
                                                                          'is_aad_joined', 'device_ips',
                                                                          'risk_level', 'exposure_level',
                                                                          'health_status', 'onboarding_status',
                                                                          'device_role', 'managed_by',
                                                                          'antivirus_status', 'is_internet_facing')
    else:
        devices = Defender.objects.values('device_id', 'device_name', 'domain', 'first_seen', 'last_device_update',
                                        'os_platform', 'os_distribution', 'os_version', 'os_build',
                                        'windows_10_version', 'tags', 'group', 'is_aad_joined', 'device_ips',
                                        'risk_level', 'exposure_level', 'health_status', 'onboarding_status',
                                        'device_role', 'managed_by', 'antivirus_status', 'is_internet_facing')
    device_count = Defender.objects.count()  # Nombre total d'éléments dans la table Device

    paginator = Paginator(devices, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context['devices'] = page_obj
    context['query'] = query
    context['device_count'] = device_count


    return render(request, 'home/defender.html', context)






from django.shortcuts import render
from .models import Askit
from django.contrib.auth.decorators import login_required

from django.shortcuts import render
from .models import Askit
from django.contrib.auth.decorators import login_required

@login_required(login_url="/login/")
def inventaire_table(request):
    context = {'segment': 'inventaire_table'}
    query = request.GET.get('q')
    numero_serie_filter = request.GET.get('numero_serie_filter')

    # Get all Askit objects from the database
    askit_objects = Askit.objects.all()

    # Apply the filters based on the query and numero_serie_filter
    if query:
        askit_objects = askit_objects.filter(modele__icontains=query)

    if numero_serie_filter:
        askit_objects = askit_objects.filter(numero_serie__icontains=numero_serie_filter)

    # Create a list to store all inventaires
    inventaires = []

    for askit in askit_objects:
        # Extract the category from the 'categorie_complete' column
        category = askit.categorie_complete.rsplit('/', 1)[-1]

        # Append the information of the current askit to the inventaires list
        inventaires.append({
            'categorie_complete': category,
            'marque': askit.marque,
            'modele': askit.modele,
            'code_materiel': askit.code_materiel,
            'identifiant_reseau': askit.identifiant_reseau,
            'numero_serie': askit.numero_serie,
            'adresse_ip': askit.adresse_ip,
            'memoire': askit.memoire,
            'statut': askit.statut,
            'utilisateur_principal': askit.utilisateur_principal,
            'id_user': askit.id_user,
            'date_depart_user': askit.date_depart_user,
            'dernier_login_connexion': askit.dernier_login_connexion,
            'localisation_dernier_niveau': askit.localisation_dernier_niveau,
            'emplacement': askit.emplacement,
            'departement': askit.departement,
            'date_livraison': askit.date_livraison,
            'date_premiere_installation': askit.date_premiere_installation,
            'date_installation': askit.date_installation,
            'dernier_inventaire_discovery': askit.dernier_inventaire_discovery,
            'dernier_inventaire_physique': askit.dernier_inventaire_physique,
            'date_sortie': askit.date_sortie,
            'commentaire': askit.commentaire,
            # Add other fields as needed
        })

    context['inventaires'] = inventaires
    context['query'] = query

    # Get unique categories from the askit objects
    categories = set(item['categorie_complete'] for item in inventaires)
    context['categories'] = sorted(categories)

    # Handle the category selection from the drop-down menu
    selected_category = request.GET.get('category_select')
    if selected_category:
        filtered_inventaires = filter_by_category(inventaires, selected_category)
        context['selected_category'] = selected_category
        context['inventaires'] = filtered_inventaires

    return render(request, 'home/askit.html', context)



def filter_by_category(inventaires, category):
    if category == "":
        return inventaires

    return [item for item in inventaires if item['categorie_complete'] == category]







@login_required(login_url="/login/")
def page_404(request):
    context = {}
    # Votre code spécifique à la page 404 ici
    # ...
    return render(request, 'home/page-404.html', context)


@login_required(login_url="/login/")
def page_500(request):
    context = {}
    # Votre code spécifique à la page 500 ici
    # ...
    return render(request, 'home/page-500.html', context)

# views.py
@login_required(login_url="/login/")
def sentinels_table(request):
    context = {'segment': 'sentinels_table'}
    query = request.GET.get('q')

    if query:
        sentinels = Sentinels.objects.filter(endpoint_name__icontains=query).values('endpoint_name', 'site', 'last_logged_in_user', 'os_username', 'group', 'tags',
                                         'domain', 'account', 'console_visible_ip', 'agent_version', 'serial_number',
                                         'last_active', 'subscribed_on', 'health_status', 'device_type', 'model_name',
                                         'os', 'os_version', 'architecture', 'memory', 'cpu_count', 'cpu_type', 'core_count',
                                         'management_connectivity', 'network_status', 'update_status', 'scan_status',
                                         'mac_addresses', 'ip_addresses', 'last_reported_ip', 'pending_uninstall',
                                         'disk_encryption', 'vulnerability_status', 'agent_uuid', 'agent_id',
                                         'customer_identifier', 'console_migration_status', 'locations', 'operational_state',
                                         'operational_state_expiration', 'last_reboot_date', 'installer_type',
                                         'reboot_required_due_to_threat', 'user_action_required', 'remote_profiling_state',
                                         'remote_profiling_expiration', 'storage_type', 'storage_name', 'cloud_account',
                                         'cloud_location', 'cloud_network', 'cloud_image', 'cloud_tags', 'cloud_instance_size',
                                         'cloud_instance_id', 'cloud_security_group', 'cluster_name', 'k8s_type', 'k8s_version',
                                         'agent_namespace', 'agent_pod_name', 'k8s_node_name', 'k8s_node_labels',
                                         'is_uninstalled', 'decommissioned_at')
    else:
        sentinels = Sentinels.objects.values('endpoint_name', 'site', 'last_logged_in_user', 'os_username', 'group', 'tags',
                                         'domain', 'account', 'console_visible_ip', 'agent_version', 'serial_number',
                                         'last_active', 'subscribed_on', 'health_status', 'device_type', 'model_name',
                                         'os', 'os_version', 'architecture', 'memory', 'cpu_count', 'cpu_type', 'core_count',
                                         'management_connectivity', 'network_status', 'update_status', 'scan_status',
                                         'mac_addresses', 'ip_addresses', 'last_reported_ip', 'pending_uninstall',
                                         'disk_encryption', 'vulnerability_status', 'agent_uuid', 'agent_id',
                                         'customer_identifier', 'console_migration_status', 'locations', 'operational_state',
                                         'operational_state_expiration', 'last_reboot_date', 'installer_type',
                                         'reboot_required_due_to_threat', 'user_action_required', 'remote_profiling_state',
                                         'remote_profiling_expiration', 'storage_type', 'storage_name', 'cloud_account',
                                         'cloud_location', 'cloud_network', 'cloud_image', 'cloud_tags', 'cloud_instance_size',
                                         'cloud_instance_id', 'cloud_security_group', 'cluster_name', 'k8s_type', 'k8s_version',
                                         'agent_namespace', 'agent_pod_name', 'k8s_node_name', 'k8s_node_labels',
                                         'is_uninstalled', 'decommissioned_at')

    paginator = Paginator(sentinels, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context['sentinels'] = page_obj
    context['query'] = query

    return render(request, 'home/sentinels.html', context)


from django.core.paginator import Paginator

@login_required(login_url="/login/")
def ad_model(request):
    context = {'segment': 'ad_model'}

    search_query = request.GET.get('search')
    ADs = AD.objects.all().values('nom', 'type', 'description')

    if search_query:
        ADs = ADs.filter(nom__icontains=search_query)

    paginator = Paginator(ADs, 10)  # 10 éléments par page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context['ADs'] = page_obj
    context['search_query'] = search_query

    return render(request, 'home/ad.html', context)

@login_required(login_url="/login/")


@login_required(login_url="/login/")

def ad_view(request):
    # Votre vue pour afficher les données AD
    ads = AD.objects.all().values('nom', 'type', 'description')
    context = {
        'ads': ads
    }
    return render(request, 'home/ad.html', context)


@login_required(login_url="/login/")




@login_required(login_url="/login/")

def upload_file_computer(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            if file.name.endswith('.csv'):
                # Lecture du fichier CSV avec pandas
                csv_data = pd.read_csv(file, sep=';')

                # Traitement des données et ajout à la base de données
                for _, row in csv_data.iterrows():
                    computer = Sophos(
                        health_status=row.get('Health Status'),
                        name=row.get('Name'),
                        ip=row.get('IP'),
                        os=row.get('OS'),
                        protection=row.get('Protection'),
                        last_user=row.get('Last user'),
                        last_active=row.get('Last active'),
                        computer_group=row.get('Group'),
                        tamper_protection=row.get('Tamper protection')
                    )
                    computer.save()

                # Redirection vers la page des ordinateurs
                return redirect('computer_table')
            else:
                form.add_error('file', 'Invalid file format. Please upload a CSV file.')
    else:
        form = UploadFileForm()

    context = {
        'form': form
    }

    return render(request, 'home/upload.html', context)


@login_required(login_url="/login/")

def upload_file_inventaire(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            if file.name.endswith('.csv'):
                csv_data = pd.read_csv(file, sep=';')

                for _, row in csv_data.iterrows():
                    inventaire = Askit(
                        categorie_complete=row.get('Catégorie complète'),
                        marque=row.get('Marque'),
                        modele=row.get('Modèle'),
                        code_materiel=row.get('Code matériel'),
                        identifiant_reseau=row.get('Identifiant réseau'),
                        numero_serie=row.get('N° de série'),
                        adresse_ip=row.get('Adresse IP'),
                        memoire=row.get('Mémoire'),
                        statut=row.get('Statut'),
                        utilisateur_principal=row.get('Utilisateur principal'),
                        id_user=row.get('ID user'),
                        date_depart_user=row.get('Date départ user '),
                        dernier_login_connexion=row.get('Dernier login de connexion'),
                        localisation_dernier_niveau=row.get('Localisation (dernier niveau)'),
                        emplacement=row.get('Emplacement'),
                        departement=row.get('Département'),
                        date_livraison=row.get('Date de livraison'),
                        date_premiere_installation=row.get('Date premiere installation'),
                        date_installation=row.get("Date d'installation"),
                        dernier_inventaire_discovery=row.get('Dernier inventaire Discovery'),
                        dernier_inventaire_physique=row.get('Dernier inventaire physique'),
                        date_sortie=row.get('Date de sortie'),
                        commentaire=row.get('Commentaire'),
                    )
                    inventaire.save()

                # Redirection vers la page des inventaires
                return redirect('inventaire_table')
            else:
                form.add_error('file', 'Invalid file format. Please upload a CSV file.')
    else:
        form = UploadFileForm()

    context = {
        'form': form
    }

    return render(request, 'home/upload_inventaire.html', context)


@login_required(login_url="/login/")

def delete_ad(request, ad_nom):
    ad = AD.objects.get(nom=ad_nom)
    ad.delete()
    return redirect('ad_model')

@login_required(login_url="/login/")

def edit_ad(request, pk):
    ad = get_object_or_404(AD, pk=pk)

    if request.method == 'POST':
        form = ADForm(request.POST, instance=ad)
        if form.is_valid():
            new_ad = form.save(commit=False)
            new_ad.nom = form.cleaned_data['nom']
            new_ad.type = form.cleaned_data['type']
            new_ad.description = form.cleaned_data['description']
            new_ad.save()
            return redirect('ad_model')
    else:
        form = ADForm(instance=ad)

    return render(request, 'home/edit_ad.html', {'form': form})


@login_required(login_url="/login/")

def search(request):
    query = request.GET.get('query')
    results = {}

    if query:
        computer_results = Sophos.objects.filter(name__icontains=query)
        inventaire_results = Askit.objects.filter(identifiant_reseau__icontains=query)
        sentinels_results = Sentinels.objects.filter(endpoint_name__icontains=query)
        ad_results = AD.objects.filter(nom__icontains=query)
        device_results = Defender.objects.filter(device_name__icontains=query)

        if computer_results:
            results['Sophos'] = computer_results

        if inventaire_results:
            results['Askit'] = inventaire_results

        if sentinels_results:
            results['Sentinels'] = sentinels_results

        if ad_results:
            results['AD'] = ad_results

        if device_results:
            results['Defender'] = device_results

    context = {
        'query': query,
        'results': results
    }

    return render(request, 'home/search_result.html', context)


@login_required(login_url="/login/")
def edit_profile(request):
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('profile')
    else:
        form = UserProfileForm(instance=request.user)

    return render(request, 'home/page-user.html', {'form': form})



def upload_file_device(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            if file.name.endswith('.csv'):
                # Read the CSV file using pandas
                csv_data = pd.read_csv(file, sep=';')

                # Process the data and add to the database
                for _, row in csv_data.iterrows():
                    is_aad_joined = row.get('Is AAD Joined')
                    if pd.isnull(is_aad_joined):
                        is_aad_joined = False

                    is_internet_facing = row.get('Is Internet Facing')
                    if pd.isnull(is_internet_facing):
                        is_internet_facing = False

                    device = Defender(
                        device_id=row.get('Device ID'),
                        device_name=row.get('Device Name'),
                        domain=row.get('Domain'),
                        first_seen=row.get('First Seen'),
                        last_device_update=row.get('Last device update'),
                        os_platform=row.get('OS Platform'),
                        os_distribution=row.get('OS Distribution'),
                        os_version=row.get('OS Version'),
                        os_build=row.get('OS Build'),
                        windows_10_version=row.get('Windows 10 Version'),
                        tags=row.get('Tags'),
                        group=row.get('Group'),
                        is_aad_joined=is_aad_joined,
                        device_ips=row.get('Device IPs'),
                        risk_level=row.get('Emplacement'),
                        exposure_level=row.get('Exposure Level'),
                        health_status=row.get('Health Status'),
                        onboarding_status=row.get('Onboarding Status'),
                        device_role=row.get('Device Role'),
                        managed_by=row.get('Managed By'),
                        antivirus_status=row.get('Antivirus status'),
                        is_internet_facing=is_internet_facing,
                    )
                    device.save()

                # Redirect to the inventory page
                return redirect('device_table')
            else:
                form.add_error('file', 'Invalid file format. Please upload a CSV file.')
    else:
        form = UploadFileForm()

    context = {
        'form': form
    }

    return render(request, 'home/upload_device.html', context)



import math


def upload_file_sentinels(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            if file.name.endswith('.csv'):
                csv_data = pd.read_csv(file, sep=';')

                for _, row in csv_data.iterrows():
                    cpu_count = row.get('CPU Count')
                    if math.isnan(cpu_count):
                        cpu_count = None

                    sentinels = Sentinels(
                        endpoint_name=row.get('Endpoint Name'),
                        site=row.get('Site'),
                        last_logged_in_user=row.get('Last Logged In User'),
                        os_username=row.get('OS Username'),
                        group=row.get('Group'),
                        tags=row.get('Tags'),
                        domain=row.get('Domain'),
                        account=row.get('Account'),
                        console_visible_ip=row.get('Console Visible IP'),
                        agent_version=row.get('Agent Version'),
                        serial_number=row.get('Serial Number'),
                        last_active=row.get('Last Active'),
                        subscribed_on=row.get('Subscribed On'),
                        health_status=row.get('Health Status'),
                        device_type=row.get('Device Type'),
                        model_name=row.get('Model Name'),
                        os=row.get('OS'),
                        os_version=row.get('OS Version'),
                        architecture=row.get('Architecture'),
                        memory=row.get('Memory'),
                        cpu_count=cpu_count,
                        cpu_type=row.get('CPU Type'),
                        core_count=row.get('Core Count'),
                        management_connectivity=row.get('Management Connectivity'),
                        network_status=row.get('Network Status'),
                        update_status=row.get('Update Status'),
                        scan_status=row.get('Scan Status'),
                        mac_addresses=row.get('MAC Addresses'),
                        ip_addresses=row.get('IP Addresses'),
                        last_reported_ip=row.get('Last Reported IP'),
                        pending_uninstall=row.get('Pending Uninstall'),
                        disk_encryption=row.get('Disk Encryption'),
                        vulnerability_status=row.get('Vulnerability Status'),
                        agent_uuid=row.get('Agent UUID'),
                        agent_id=row.get('Agent ID'),
                        customer_identifier=row.get('Customer Identifier'),
                        console_migration_status=row.get('Console Migration Status'),
                        locations=row.get('Locations'),
                        operational_state=row.get('Operational State'),
                        operational_state_expiration=row.get('Operational State Expiration'),
                        last_reboot_date=row.get('Last Reboot Date'),
                        installer_type=row.get('Installer Type'),
                        reboot_required_due_to_threat=row.get('Reboot Required due to Threat'),
                        user_action_required=row.get('User Action Required'),
                        remote_profiling_state=row.get('Remote Profiling State'),
                        remote_profiling_expiration=row.get('Remote Profiling Expiration'),
                        storage_type=row.get('Storage Type'),
                        storage_name=row.get('Storage Name'),
                        cloud_account=row.get('Cloud Account'),
                        cloud_location=row.get('Cloud Location'),
                        cloud_network=row.get('Cloud Network'),
                        cloud_image=row.get('Cloud Image'),
                        cloud_tags=row.get('Cloud Tags'),
                        cloud_instance_size=row.get('Cloud Instance Size'),
                        cloud_instance_id=row.get('Cloud Instance ID'),
                        cloud_security_group=row.get('Cloud Security Group'),
                        cluster_name=row.get('Cluster Name'),
                        k8s_type=row.get('K8s Type'),
                        k8s_version=row.get('K8s Version'),
                        agent_namespace=row.get('Agent Namespace'),
                        agent_pod_name=row.get('Agent Pod Name'),
                        k8s_node_name=row.get('K8s Node Name'),
                        k8s_node_labels=row.get('K8s Node Labels'),
                        is_uninstalled=row.get('Is Uninstalled'),
                        decommissioned_at=row.get('Decommissioned at'),
                    )
                    sentinels.save()

                return redirect('sentinels_table')
            else:
                form.add_error('file', 'Invalid file format. Please upload a CSV file.')
    else:
        form = UploadFileForm()

    context = {
        'form': form
    }

    return render(request, 'home/upload_sentinels.html', context)


def anomalie_sophos(request):
    # Durée d'inactivité considérée comme une anomalie (en minutes)
    anomaly_threshold = 60

    # Durée d'inactivité pour considérer un risque (un mois en minutes)
    risk_threshold = 30 * 24 * 60

    # Collecte des données des systèmes Sophos depuis la base de données
    systems = Sophos.objects.all()

    anomalies = []

    # Vérification de l'inactivité pour chaque système Sophos
    for system in systems:
        last_active_str = system.last_active
        if last_active_str is not None:
            last_active = datetime.strptime(last_active_str, "%b %d, %Y %I:%M %p")
            current_time = datetime.now()
            inactive_duration = current_time - last_active
            inactive_duration_minutes = inactive_duration.total_seconds() / 60

            if inactive_duration_minutes > risk_threshold:
                risk_level = "High"
            elif inactive_duration > timedelta(minutes=anomaly_threshold):
                risk_level = "Medium"
            else:
                risk_level = "Low"

            anomalies.append({
                'system_name': system.name,
                'last_active': last_active_str,
                'inactive_duration': inactive_duration,
                'risk_level': risk_level,
            })

    context = {
        'anomalies': anomalies
    }

    return render(request, 'home/anomalie_sophos.html', context)


from datetime import datetime, timedelta
from django.shortcuts import render
from .models import Askit, Sophos, Defender, Sentinels
import re



def search_model(identifiant_reseau, model_name):
    if model_name == 'Sophos':
        return Sophos.objects.filter(name__icontains=identifiant_reseau).first()
    elif model_name == 'Defender':
        return Defender.objects.filter(device_name__icontains=identifiant_reseau).first()
    elif model_name == 'Sentinels':
        return Sentinels.objects.filter(endpoint_name__icontains=identifiant_reseau).first()
    else:
        return None

def conformity_check(request, identifiant_reseau=None):
    if request.method == 'POST':
        identifiant_reseau = request.POST.get('identifiant_reseau')

    conformity_status = 'Conforme'
    non_conformity_criterias = []

    if identifiant_reseau is None:
        # Le formulaire n'a pas été soumis ou l'identifiant réseau n'est pas fourni
        return render(request, 'home/conformity_check.html')

    # Vérification du modèle Sophos
    sophos = search_model(identifiant_reseau, 'Sophos')
    if not sophos:
        non_conformity_criterias.append('Modèle Sophos introuvable')
        conformity_status = 'Non conforme'
    else:
        sophos_attributes = ['health_status', 'last_active']
        for attribute in sophos_attributes:
            if getattr(sophos, attribute, None) is None or str(getattr(sophos, attribute, '')).lower() in (
            'null', 'nan'):
                non_conformity_criterias.append(f'Attribut manquant dans le modèle Sophos: {attribute}')
                conformity_status = 'Non conforme'
        if sophos.health_status != 'Healthy':
            conformity_status = 'Non conforme'
            non_conformity_criterias.append('Problème health status en Sophos')
        elif sophos.last_active:
            last_active = datetime.strptime(sophos.last_active, '%b %d, %Y %I:%M %p')
            if last_active < datetime.now() - timedelta(days=30):
                conformity_status = 'Non conforme'
                non_conformity_criterias.append('Problème last active en Sophos')
        else:
            non_conformity_criterias.append('Valeur last active manquante en Sophos')
            conformity_status = 'Non conforme'

    # Vérification du modèle Sentinels
    sentinels = search_model(identifiant_reseau, 'Sentinels')
    if not sentinels:
        non_conformity_criterias.append('Modèle Sentinels introuvable')
        conformity_status = 'Non conforme'
    else:
        sentinels_attributes = ['site', 'last_logged_in_user', 'os_username', 'group', 'tags', 'domain', 'account',
                                'console_visible_ip', 'agent_version', 'serial_number', 'last_active', 'subscribed_on',
                                'health_status', 'device_type', 'model_name', 'os', 'os_version', 'architecture',
                                'memory', 'cpu_count', 'cpu_type', 'core_count', 'management_connectivity',
                                'network_status', 'update_status', 'scan_status', 'mac_addresses', 'ip_addresses',
                                'last_reported_ip', 'pending_uninstall']
        for attribute in sentinels_attributes:
            if getattr(sentinels, attribute, None) is None or str(getattr(sentinels, attribute, '')).lower() in (
            'null', 'nan'):
                non_conformity_criterias.append(f'Attribut manquant dans le modèle sentinels: {attribute}')
                conformity_status = 'Non conforme'

        if not sentinels.scan_status.startswith('Completed'):
            conformity_status = 'Non conforme'
            non_conformity_criterias.append('Problème en scan status: not Completed en Sentinels ou valeur manquante')
        else:
            match = re.search(r'\((.*?)\)', sentinels.scan_status)
            if match:
                scan_date_str = match.group(1).strip()  # Supprimer les espaces avant et après la chaîne de date
                try:
                    scan_date = datetime.strptime(scan_date_str, '%b %d, %Y %I:%M:%S %p')
                    if scan_date < datetime.now() - timedelta(days=120):
                        conformity_status = 'Non conforme'
                        non_conformity_criterias.append('Problème en scan status en Sentinels:Date')
                except ValueError:
                    # Le format de date ne correspond pas au format attendu
                    conformity_status = 'Non conforme'
                    non_conformity_criterias.append('Format de date incorrect pour scan status en Sentinels')
            if sentinels.last_active:
                last_active = datetime.strptime(sentinels.last_active, '%b %d, %Y %I:%M:%S %p')
                if last_active < datetime.now() - timedelta(days=30):
                    conformity_status = 'Non conforme'
                    non_conformity_criterias.append('Problème en last active en Sentinels:Date ')


    # Vérification du modèle Defender
    defender = search_model(identifiant_reseau, 'Defender')
    if not defender:
        non_conformity_criterias.append('Modèle Defender introuvable')
        conformity_status = 'Non conforme'
    else:
        defender_attributes = ['exposure_level', 'domain', 'first_seen', 'last_device_update', 'os_platform',
                               'os_distribution', 'os_version', 'os_build', 'windows_10_version', 'tags', 'group',
                               'is_aad_joined', 'device_ips', 'risk_level', 'exposure_level', 'health_status',
                               'onboarding_status', 'device_role', 'managed_by', 'antivirus_status',
                               'is_internet_facing']
        for attribute in defender_attributes:
            if getattr(defender, attribute, None) is None or str(getattr(defender, attribute, '')).lower() in (
            'null', 'nan'):
                non_conformity_criterias.append(f'Attribut manquant dans le modèle Defender: {attribute}')
                conformity_status = 'Non conforme'

        if defender.exposure_level in ('Medium', 'High'):
            conformity_status = 'Non conforme'
            non_conformity_criterias.append('Problème en exposure level en Defender')
        elif defender.exposure_level =='No data available':
            conformity_status = 'Non conforme'
            non_conformity_criterias.append('Problème en exposure level en Defender il faut le verifier')
        elif defender.antivirus_status == 'Not updated':
            conformity_status = 'Non conforme'
            non_conformity_criterias.append('Problème en antivirus status en Defender')
        elif defender.health == 'Inactive':
            conformity_status = 'Non conforme'
            non_conformity_criterias.append('Problème en Health status en Defender')
        elif defender.last_device_update:
            last_device_update = datetime.strptime(defender.last_device_update, '%d/%m/%Y %H:%M')
            if last_device_update < datetime.now() - timedelta(days=30):
                conformity_status = 'Non conforme'
                non_conformity_criterias.append('Problème en last device update en Defender')


    return render(request, 'home/conformity_check.html', {
        'conformity_status': conformity_status,
        'non_conformity_criterias': non_conformity_criterias,
    })


from .models import AD
from datetime import datetime, timedelta


def detect_anomalies_view(request):
    # Liste des modèles AD
    ad_models = AD.objects.all()

    devices = []
    for ad_obj in ad_models:
        identifier = ad_obj.nom
        device = {'identifier': identifier}

        # Vérification pour le modèle Sophos
        try:
            sophos_obj = search_model(identifier, 'Sophos')
            if not sophos_obj:
                device['existance'] = {'value': 'Introuvable', 'status': 'Invalide'}
            else:
                device['existance'] = {'value': 'Trouvé', 'status': 'Valide'}
                # Test Last Active
                if sophos_obj.last_active and (datetime.now() - datetime.strptime(str(sophos_obj.last_active),'%b %d, %Y %I:%M %p')) <= timedelta(days=34):
                    device['last_active'] = {'value': sophos_obj.last_active, 'status': 'Valide'}
                else:
                    device['last_active'] = {'value': sophos_obj.last_active, 'status': 'Invalide'}

                # Test Health Status
                if sophos_obj.health_status == 'Healthy':
                    device['health_status'] = {'value': sophos_obj.health_status, 'status': 'Valide'}
                else:
                    device['health_status'] = {'value': sophos_obj.health_status, 'status': 'Invalide'}

        except Sophos.DoesNotExist:
            device['existance'] = {'value': ' Introuvable', 'status': 'Invalide'}

        # Vérification pour le modèle Sentinels
        try:
            sentinels_obj = search_model(identifier, 'Sentinels')
            if not sentinels_obj:
                device['existance_sentinels'] = {'value': 'Introuvable', 'status': 'Invalide'}
            else:
                device['existance_sentinels'] = {'value': 'Trouvé', 'status': 'Valide'}

                # Test Scan Status
                if sentinels_obj.scan_status.startswith('Completed'):
                    device['scan_status'] = {'value': sentinels_obj.scan_status, 'status': 'Valide'}
                else:
                    device['scan_status'] = {'value': sentinels_obj.scan_status, 'status': 'Invalide'}

                # Test Last Active for Sentinels
                if sentinels_obj.last_active and (datetime.now() - datetime.strptime(str(sentinels_obj.last_active),
                                                                                     '%b %d, %Y %I:%M:%S %p')) <= timedelta(
                        days=90):
                    device['last_active_sentinels'] = {'value': sentinels_obj.last_active, 'status': 'Valide'}
                else:
                    device['last_active_sentinels'] = {'value': sentinels_obj.last_active, 'status': 'Invalide'}

        except Sentinels.DoesNotExist:
            device['existance_sentinels'] = {'value': 'Introuvable', 'status': 'Invalide'}

        # Vérification pour le modèle Defender
        try:
            defender_obj = search_model(identifier, 'Defender')
            if not defender_obj:
                device['existance_defender'] = {'value': 'Introuvable', 'status': 'Invalide'}
            else:
                device['existance_defender'] = {'value': 'Trouvé', 'status': 'Valide'}

                # Test Exposure Level and Last Device Update
                if defender_obj:
                    device['exposure_level'] = {'value': defender_obj.exposure_level,'status': 'Valide' if defender_obj.exposure_level in ['Medium','High'] else 'Invalide'}
                else:
                    device['exposure_level'] = {'value': defender_obj.exposure_level, 'status': 'Invalide'}

                # Check Antivirus Status for Defender
                if defender_obj:
                    device['antivirus_status'] = {'value': defender_obj.antivirus_status,'status': 'Valide' if defender_obj.antivirus_status == 'Updated' else 'Invalide'}
                else:
                    device['antivirus_status'] = {'value': defender_obj.antivirus_status, 'status': 'Invalide'}
                if defender_obj:
                    device['health_status_d'] = {'value': defender_obj.health_status,'status': 'Valide' if defender_obj.health_status == 'Active' else 'Invalide'}
                else:
                    device['health_status_d'] = {'value': defender_obj.health_status, 'status': 'Invalide'}

                # Check Last Device Update for Defender
                if defender_obj and defender_obj.last_device_update and (
                        datetime.now() - datetime.strptime(str(defender_obj.last_device_update),'%d/%m/%Y %H:%M')) <= timedelta(days=30):
                    device['last_device_update'] = {'value': defender_obj.last_device_update, 'status': 'Valide'}
                else:
                    device['last_device_update'] = {'value': defender_obj.last_device_update, 'status': 'Invalide'}

        except Defender.DoesNotExist:
            device['existance_defender'] = {'value': 'Introuvable', 'status': 'Invalide'}

        devices.append(device)

    # Liste des noms de devices ayant des problèmes
    device_problems = [device['identifier'] for device in devices if 'status' in device and device['status'] == 'Invalide']

    context = {'devices': devices, 'device_problems': device_problems}


    return render(request, 'home/conformity_check.html', context)

# views.py
from django.shortcuts import render
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from django.conf import settings

def categorie(request):
    # Extract data from the Askit database and create a DataFrame
    # Assuming AskitModel is the model that represents the Askit database
    askit_models = Askit.objects.all()
    data = []
    for askit_obj in askit_models:
        data.append({
            'identifier': askit_obj.identifier,
            'categorie_complete': askit_obj.categorie_complete,
            # Add other relevant features here
        })
    df = pd.DataFrame(data)

    # Preprocess data
    df['categorie_complete'] = df['categorie_complete'].fillna('Unknown')  # Handle missing values
    le = LabelEncoder()
    df['category_encoded'] = le.fit_transform(df['categorie_complete'])

    # Define features and target
    features = ['category_encoded']  # Add other features if needed
    target = 'target_column_name'  # Replace 'target_column_name' with the actual target column name

    # Split the data into training and testing sets (you may want to adjust the ratio)
    train_df = df.sample(frac=0.8, random_state=42)
    test_df = df.drop(train_df.index)

    # Train the RandomForestClassifier
    model = RandomForestClassifier(random_state=42)
    model.fit(train_df[features], train_df[target])

    # Make predictions on the testing set
    predictions = model.predict(test_df[features])

    # Add the predictions to the test_df
    test_df['predicted_category'] = le.inverse_transform(predictions)

    context = {'devices': test_df.to_dict(orient='records')}  # Convert DataFrame to dictionary

    return render(request, 'home/categorie.html', context)


from django.shortcuts import render
from .models import Askit
from collections import defaultdict

from django.shortcuts import render
from .models import Askit
from collections import defaultdict

def verifier_doublons(request):
    base_de_donnees = Askit.objects.all()
    compteur_elements = defaultdict(int)

    for element in base_de_donnees:
        identifiant_reseau = element.identifiant_reseau
        compteur_elements[identifiant_reseau] += 1


    return render(request, 'home/verficationd.html', {'compteur_elements': dict(compteur_elements)})



@login_required(login_url="/login/")
def sap_table(request):
    context = {'segment': 'sap_table'}
    query = request.GET.get('q')

    if query:
        sap_items = SAP.objects.filter(numero_serie__icontains=query).values(
            'doma',
            'division',
            'localisat',
            'local',
            'immobilis',
            'n_s',
            'n_regr_immobilisation',
            'numero_inventaire',
            'designation_immobilisatio1',
            'designation_immobilisatio2',
            'code_designat',
            'mise_serv',
            'comment_invent',
            'date_inv',
            'numero_serie',
            'n_immatric',
            'n_projet_investissement',
            'disponibilite',
            'fabricant_immobilisation',
            'fournisseur1',
            'fournisseur2',
            'quantite',
            'uq',
            'compte_cap',
            'cat_immo',
            'centre',
            'val_acq_fin_ex',
            'dev_amortissement_fin_ex',
            'amortissement_fin_ex',
            'val_cpt_fin_ex',
            'dev_mise_hs',
            'mise_hs',
            'immo_d_orig',
            'n_s_iec',
            'mo',
            'valeur_d_origine',
            'dev_valeur_man_patr',
            'valeur_man_patr',
            'cod_am',
            'ut',
            'per',
            'debut_ad'
        )
    else:
        sap_items = SAP.objects.values(
            'doma',
            'division',
            'localisat',
            'local',
            'immobilis',
            'n_s',
            'n_regr_immobilisation',
            'numero_inventaire',
            'designation_immobilisatio1',
            'designation_immobilisatio2',
            'code_designat',
            'mise_serv',
            'comment_invent',
            'date_inv',
            'numero_serie',
            'n_immatric',
            'n_projet_investissement',
            'disponibilite',
            'fabricant_immobilisation',
            'fournisseur1',
            'fournisseur2',
            'quantite',
            'uq',
            'compte_cap',
            'cat_immo',
            'centre',
            'val_acq_fin_ex',
            'dev_amortissement_fin_ex',
            'amortissement_fin_ex',
            'val_cpt_fin_ex',
            'dev_mise_hs',
            'mise_hs',
            'immo_d_orig',
            'n_s_iec',
            'mo',
            'valeur_d_origine',
            'dev_valeur_man_patr',
            'valeur_man_patr',
            'cod_am',
            'ut',
            'per',
            'debut_ad'
        )

    sap_item_count = SAP.objects.count()  # Nombre total d'éléments dans la table SAP

    paginator = Paginator(sap_items, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context['sap_items'] = page_obj
    context['query'] = query
    context['sap_item_count'] = sap_item_count

    return render(request, 'home/sap_table.html', context)


# Dans le fichier apps/home/views.py
import csv
import pandas as pd
from django.shortcuts import render, redirect
from .models import SAP
from .form import UploadFileForm
from django.contrib.auth.decorators import login_required

@login_required(login_url="/login/")
def upload_file_sap(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            if file.name.endswith('.csv'):
                try:
                    csv_data = pd.read_csv(file)
                    for _, row in csv_data.iterrows():
                        sap_item = SAP(
                            id=row.get('id'),
                            doma=row.get('DomA'),
                            division=row.get('Div.'),
                            localisat=row.get('Localisat.'),
                            local=row.get('Local'),
                            immobilis=row.get('Immobilis.'),
                            n_s=row.get('NºS.'),
                            n_regr_immobilisation=row.get('N°regr.immo.'),
                            numero_inventaire=row.get('Numéro d\'inventaire'),
                            designation_immobilisatio1=row.get('Désignation de l\'immobilisatio'),
                            designation_immobilisatio2=row.get('Désignation de l\'immobilisatio'),
                            code_designat=row.get('Code désignat.'),
                            mise_serv=row.get('Mise serv.'),
                            comment_invent=row.get('Comment.invent.'),
                            date_inv=row.get('Date inv.'),
                            numero_serie=row.get('Numéro de série'),
                            n_immatric=row.get('N° d\'immatric.'),
                            n_projet_investissement=row.get('N° de projet d\'investissement'),
                            disponibilite=row.get('Disponibilité'),
                            fabricant_immobilisation=row.get("Fabricant de l'immobilisation"),
                            fournisseur1=row.get('Fourn.'),
                            fournisseur2=row.get('Fournisseur'),
                            quantite=row.get('Quantité'),
                            uq=row.get('UQ'),
                            compte_cap=row.get('Compte CAP'),
                            cat_immo=row.get('Cat.immo'),
                            centre=row.get('Centre'),
                            val_acq_fin_ex=row.get('ValAcqFinEx'),
                            dev_val_acq_fin_ex=row.get('Dev.'),
                            amortissement_fin_ex=row.get('Amo.fin.ex.'),
                            dev_amortissement_fin_ex=row.get('Dev. Amortissement Fin Ex.'),
                            val_cpt_fin_ex=row.get('ValCptFinEx'),
                            mise_hs=row.get('Mise h.s.'),
                            dev_mise_hs=row.get('Dev. Mise h.s.'),
                            immo_d_orig=row.get("Immo.d'orig."),
                            n_s_iec=row.get('N°S. IEC'),
                            mo=row.get('Mo'),
                            valeur_d_origine=row.get("Valeur d'origine"),
                            dev_valeur_man_patr=row.get('Dev. Valeur man. patr.'),
                            valeur_man_patr=row.get('Valeur man. patr.'),
                            cod_am=row.get('CodAm'),
                            ut=row.get('Ut.'),
                            per=row.get('Pér'),
                            debut_ad=row.get('Début AD'),
                        )
                        sap_item.save()
                    # Redirection vers la page de la table SAP
                    return redirect('sap_table')
                except csv.Error as e:
                    # Gestion de l'erreur CSV
                    form.add_error('file', f"CSV Error: {str(e)}")
            else:
                form.add_error('file', 'Invalid file format. Please upload a CSV file.')
    else:
        form = UploadFileForm()

    context = {
        'form': form
    }

    return render(request, 'home/upload_sap.html', context)


from django.shortcuts import render
from datetime import datetime, timedelta
from .models import Askit, SAP

def verifier_laskit_dans_sap(request):
    # Récupérer tous les objets Askit
    laskit_objects = Askit.objects.all()

    devices = []
    for laskit_obj in laskit_objects:
        identifier = laskit_obj.numero_serie
        device = {'identifier': identifier}

        # Vérifier si l'élément existe dans le modèle SAP
        sap_objects = SAP.objects.filter(numero_serie=identifier)
        if sap_objects.exists():
            device['existance'] = {'value': 'Trouvé', 'status': 'Valide'}
            sap_obj = sap_objects.first()  # Get the first SAP object if multiple found
        else:
            device['existance'] = {'value': 'Introuvable', 'status': 'Invalide'}
            sap_obj = None

        # Vérifier la dernière date d'inventaire discovery dans Askit
        if pd.notna(laskit_obj.dernier_inventaire_discovery):
            try:
                date_inventaire_discovery = datetime.strptime(laskit_obj.dernier_inventaire_discovery, "%d/%m/%Y %H:%M")
                today = datetime.now()
                if (today.date() - date_inventaire_discovery.date()) > timedelta(days=90):
                    device['dernier_inventaire_discovery'] = {'value': laskit_obj.dernier_inventaire_discovery, 'status': 'Invalide'}
                else:
                    device['dernier_inventaire_discovery'] = {'value': laskit_obj.dernier_inventaire_discovery, 'status': 'Valide'}
            except ValueError:
                device['dernier_inventaire_discovery'] = {'value': 'Invalid date format', 'status': 'Invalide'}
        else:
            device['dernier_inventaire_discovery'] = {'value': 'N/A', 'status': 'Invalide'}

        # Vérifier la dernière date d'inventaire physique dans Askit
        if pd.notna(laskit_obj.dernier_inventaire_physique):
            try:
                date_inventaire_physique = datetime.strptime(laskit_obj.dernier_inventaire_physique, "%d/%m/%Y")
                today = datetime.now().date()
                if (today - date_inventaire_physique.date()) > timedelta(days=365):
                    device['dernier_inventaire_physique'] = {'value': laskit_obj.dernier_inventaire_physique, 'status': 'Invalide'}
                else:
                    device['dernier_inventaire_physique'] = {'value': laskit_obj.dernier_inventaire_physique, 'status': 'Valide'}
            except ValueError:
                device['dernier_inventaire_physique'] = {'value': 'Invalid date format', 'status': 'Invalide'}
        else:
            device['dernier_inventaire_physique'] = {'value': 'N/A', 'status': 'Invalide'}

        devices.append(device)

    context = {'devices': devices}

    return render(request, 'home/verification.html', context)


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .form import UserProfileForm
from .models import UserProfile

@login_required(login_url="/login/")
def edit_profile(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        # Si UserProfile n'existe pas, le créer
        user_profile = UserProfile.objects.create(user=request.user)

    if request.method == "POST":
        form = UserProfileForm(request.POST, instance=user_profile)
        if form.is_valid():
            form.save()
            return redirect("/")  # Rediriger vers la page d'accueil après avoir enregistré les modifications
    else:
        form = UserProfileForm(instance=user_profile)

    return render(request, "home/page-user.html", {"form": form, "user_profile": user_profile})


from django.shortcuts import render, redirect
from .models import AD


def upload_ad_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            if file.name.endswith('.csv'):
                csv_data = pd.read_csv(file, sep=';')

                existing_ads = []
                new_ads = []

                for _, row in csv_data.iterrows():
                    ad_name = row.get('Nom')
                    ad_type = row.get('Type')
                    ad_description = row.get('Description')

                    existing_ad = AD.objects.filter(nom=ad_name).first()

                    if existing_ad:
                        existing_ads.append(existing_ad)
                    else:
                        ad = AD(nom=ad_name, type=ad_type, description=ad_description)
                        new_ads.append(ad)

                context = {
                    'existing_ads': existing_ads,
                    'new_ads': new_ads,
                }
                return render(request, 'home/confirm_upload.html', context)
            else:
                form.add_error('file', 'Invalid file format. Please upload a CSV file.')
    else:
        form = UploadFileForm()

    context = {
        'form': form
    }
    return render(request, 'home/upload.html', context)


def confirm_upload_ad(request):
    # Cette vue est déjà fournie dans le code précédent (la fenêtre modale est gérée en JavaScript)
    # Vous pouvez copier-coller la vue confirm_upload_ad du code précédent.
    pass