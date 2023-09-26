# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.db import models
from django.contrib.auth.models import User


class Sophos(models.Model):
    health_status = models.CharField(max_length=200, null=True)
    name = models.CharField(max_length=200, primary_key=True)
    ip = models.CharField(max_length=200, null=True)
    os = models.CharField(max_length=200, null=True)
    protection = models.CharField(max_length=200, null=True)
    last_user = models.CharField(max_length=200, null=True)
    last_active = models.CharField(max_length=200, null=True)
    computer_group = models.CharField(max_length=200, null=True)
    tamper_protection = models.CharField(max_length=200, null=True)

    def __str__(self):
        return self.name


class Askit(models.Model):
    categorie_complete = models.CharField(max_length=100, null=True)
    marque = models.CharField(max_length=100, null=True)
    modele = models.CharField(max_length=100, null=True)
    code_materiel = models.CharField(max_length=100, null=True)
    identifiant_reseau = models.CharField(max_length=100, primary_key=True)
    numero_serie = models.CharField(max_length=100, null=True)
    adresse_ip = models.CharField(max_length=100, null=True)
    memoire = models.FloatField(null=True)
    statut = models.CharField(max_length=100, null=True)
    utilisateur_principal = models.CharField(max_length=100, null=True)
    id_user = models.CharField(max_length=100, null=True)
    date_depart_user = models.CharField(max_length=100, null=True)
    dernier_login_connexion = models.CharField(max_length=100, null=True)
    localisation_dernier_niveau = models.CharField(max_length=100, null=True)
    emplacement = models.CharField(max_length=100, null=True)
    departement = models.FloatField(null=True)
    date_livraison = models.CharField(max_length=100, null=True)
    date_premiere_installation = models.CharField(max_length=100, null=True)
    date_installation = models.CharField(max_length=100, null=True)
    dernier_inventaire_discovery = models.CharField(max_length=100, null=True)
    dernier_inventaire_physique = models.CharField(max_length=100, null=True)
    date_sortie = models.FloatField(null=True)
    commentaire = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.numero_serie


class Sentinels(models.Model):
    endpoint_name = models.CharField(max_length=100, primary_key=True)
    site = models.CharField(max_length=100, null=True)
    last_logged_in_user = models.CharField(max_length=100, null=True)
    os_username = models.FloatField( null=True)
    group = models.CharField(max_length=100, null=True)
    tags = models.CharField(max_length=100, null=True)
    domain = models.CharField(max_length=100, null=True)
    account = models.CharField(max_length=100, null=True)
    console_visible_ip = models.CharField(max_length=100, null=True)
    agent_version = models.CharField(max_length=100, null=True)
    serial_number = models.CharField(max_length=100, null=True)
    last_active = models.CharField(max_length=100, null=True)
    subscribed_on = models.CharField(max_length=100, null=True)
    health_status = models.CharField(max_length=100, null=True)
    device_type = models.CharField(max_length=100, null=True)
    model_name = models.CharField(max_length=100, null=True)
    os = models.CharField(max_length=100, null=True)
    os_version = models.CharField(max_length=100, null=True)
    architecture = models.CharField(max_length=100, null=True)
    memory = models.CharField(max_length=100, null=True)
    cpu_count = models.IntegerField( null=True)
    cpu_type = models.CharField(max_length=100, null=True)
    core_count = models.IntegerField( null=True)
    management_connectivity = models.CharField(max_length=100, null=True)
    network_status = models.CharField(max_length=100, null=True)
    update_status = models.CharField(max_length=100, null=True)
    scan_status = models.CharField(max_length=100, null=True)
    mac_addresses = models.CharField(max_length=900, null=True)
    ip_addresses = models.CharField(max_length=2000, null=True)
    last_reported_ip = models.CharField(max_length=400, null=True)
    pending_uninstall = models.CharField(max_length=100, null=True)
    disk_encryption = models.CharField(max_length=100, null=True)
    vulnerability_status = models.CharField(max_length=100, null=True)
    agent_uuid = models.CharField(max_length=100, null=True)
    agent_id = models.CharField(max_length=100, null=True)
    customer_identifier = models.FloatField( null=True)
    console_migration_status = models.FloatField( null=True)
    locations = models.CharField(max_length=100, null=True)
    operational_state = models.CharField(max_length=100, null=True)
    operational_state_expiration = models.CharField(max_length=100, null=True)
    last_reboot_date = models.CharField(max_length=100, null=True)
    installer_type = models.CharField(max_length=100, null=True)
    reboot_required_due_to_threat = models.CharField(max_length=100, null=True)
    user_action_required = models.CharField(max_length=100, null=True)
    remote_profiling_state = models.CharField(max_length=100, null=True)
    remote_profiling_expiration = models.FloatField( null=True)
    storage_type = models.FloatField(null=True)
    storage_name = models.FloatField( null=True)
    cloud_account = models.FloatField( null=True)
    cloud_location = models.FloatField( null=True)
    cloud_network = models.FloatField( null=True)
    cloud_image = models.FloatField( null=True)
    cloud_tags = models.FloatField( null=True)
    cloud_instance_size = models.FloatField( null=True)
    cloud_instance_id = models.FloatField( null=True)
    cloud_security_group = models.FloatField( null=True)
    cluster_name = models.FloatField( null=True)
    k8s_type = models.FloatField( null=True)
    k8s_version = models.FloatField( null=True)
    agent_namespace = models.FloatField( null=True)
    agent_pod_name = models.FloatField( null=True)
    k8s_node_name = models.FloatField( null=True)
    k8s_node_labels = models.FloatField( null=True)
    is_uninstalled = models.CharField(max_length=100, null=True)
    decommissioned_at = models.FloatField( null=True)

    def __str__(self):
        return self.endpoint_name


class AD(models.Model):
    nom = models.CharField(max_length=100, primary_key=True, unique=True)
    type = models.CharField(max_length=100, null=True)
    description = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.nom


class Defender(models.Model):
    device_id = models.CharField(max_length=200, null=True)
    device_name = models.CharField(max_length=100, primary_key=True)
    domain = models.CharField(max_length=100, null=True)
    first_seen = models.CharField(max_length=100, null=True)
    last_device_update = models.CharField(max_length=100, null=True)
    os_platform = models.CharField(max_length=100, null=True)
    os_distribution = models.CharField(max_length=100, null=True)
    os_version = models.CharField(max_length=100, null=True)
    os_build = models.FloatField(null=True)
    windows_10_version = models.CharField(max_length=100, null=True)
    tags = models.FloatField(null=True)
    group = models.CharField(max_length=100, null=True)
    is_aad_joined = models.BooleanField(default=False, null=True)
    device_ips = models.CharField(max_length=2000, null=True)
    risk_level = models.CharField(max_length=100, null=True)
    exposure_level = models.CharField(max_length=100, null=True)
    health_status = models.CharField(max_length=100, null=True)
    onboarding_status = models.CharField(max_length=100, null=True)
    device_role = models.FloatField(null=True)
    managed_by = models.CharField(max_length=100, null=True)
    antivirus_status = models.CharField(max_length=100, null=True)
    is_internet_facing = models.FloatField(null=True)

    def __str__(self):
        return self.device_name


class SAP(models.Model):
    id = models.AutoField(primary_key=True)
    doma = models.CharField(max_length=255, verbose_name="DomA", null=True)
    division = models.CharField(max_length=255, verbose_name="Div.", null=True)
    localisat = models.CharField(max_length=255, verbose_name="Localisat.", null=True)
    local = models.CharField(max_length=255, verbose_name="Local", null=True)
    immobilis = models.CharField(max_length=255, verbose_name="Immobilis.", null=True)
    n_s = models.CharField(max_length=255, verbose_name="NºS.", null=True)
    n_regr_immobilisation = models.CharField(max_length=255, verbose_name="N°regr.immo.", null=True)
    numero_inventaire = models.CharField(max_length=255, verbose_name="Numéro d'inventaire", null=True)
    designation_immobilisatio1 = models.CharField(max_length=255, verbose_name="Désignation de l'immobilisatio", null=True)
    designation_immobilisatio2 = models.CharField(max_length=255, verbose_name="Désignation de l'immobilisatio", null=True)
    code_designat = models.CharField(max_length=255, verbose_name="Code désignat.", null=True)
    mise_serv = models.CharField(max_length=255, verbose_name="Mise serv.", null=True)
    comment_invent = models.CharField(max_length=255, verbose_name="Comment.invent.", null=True)
    date_inv = models.DateField(verbose_name="Date inv.", null=True)
    numero_serie = models.CharField(max_length=255, verbose_name="Numéro de série", null=True)
    n_immatric = models.CharField(max_length=255, verbose_name="N° d'immatric.", null=True)
    n_projet_investissement = models.CharField(max_length=255, verbose_name="N° de projet d'investissement", null=True)
    disponibilite = models.CharField(max_length=255, verbose_name="Disponibilité", null=True)
    fabricant_immobilisation = models.CharField(max_length=255, verbose_name="Fabricant de l'immobilisation", null=True)
    fournisseur1 = models.CharField(max_length=255, verbose_name="Fourn.", null=True)
    fournisseur2 = models.CharField(max_length=255, verbose_name="Fournisseur", null=True)
    quantite = models.CharField(max_length=255, verbose_name="Quantité", null=True)
    uq = models.CharField(max_length=255, verbose_name="UQ", null=True)
    compte_cap = models.CharField(max_length=255, verbose_name="Compte CAP", null=True)
    cat_immo = models.CharField(max_length=255, verbose_name="Cat.immo", null=True)
    centre = models.CharField(max_length=255, verbose_name="Centre", null=True)
    val_acq_fin_ex = models.CharField(max_length=255, verbose_name="ValAcqFinEx", null=True)
    dev_val_acq_fin_ex = models.CharField(max_length=255, verbose_name="Dev.", null=True)
    amortissement_fin_ex = models.CharField(max_length=255, verbose_name="Amo.fin.ex.", null=True)
    dev_amortissement_fin_ex = models.CharField(max_length=255, verbose_name="Dev.", null=True)
    val_cpt_fin_ex = models.CharField(max_length=255, verbose_name="ValCptFinEx", null=True)
    dev_val_cpt_fin_ex = models.CharField(max_length=255, verbose_name="Dev.", null=True)
    mise_hs = models.CharField(max_length=255, verbose_name="Mise h.s.", null=True)
    immo_d_orig = models.CharField(max_length=255, verbose_name="Immo.d'orig.", null=True)
    n_s_iec = models.CharField(max_length=255, verbose_name="N°S. IEC", null=True)
    mo = models.CharField(max_length=255, verbose_name="Mo", null=True)
    valeur_d_origine = models.CharField(max_length=255, verbose_name="Valeur d'origine", null=True)
    dev_valeur_d_origine = models.CharField(max_length=255, verbose_name="Dev.", null=True)
    valeur_man_patr = models.CharField(max_length=255, verbose_name="Valeur man. patr.", null=True)
    dev_valeur_man_patr = models.CharField(max_length=255, verbose_name="Dev.", null=True)
    cod_am = models.CharField(max_length=255, verbose_name="CodAm", null=True)
    ut = models.CharField(max_length=255, verbose_name="Ut.", null=True)
    per = models.CharField(max_length=255, verbose_name="Pér", null=True)
    debut_ad = models.DateField(verbose_name="Début AD", null=True)

    def __str__(self):
        return self.numero_inventaire


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=10)
    about_me = models.TextField()

    def __str__(self):
        return f"{self.user.username}'s Profile"
