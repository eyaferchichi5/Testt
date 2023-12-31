# Generated by Django 4.2.2 on 2023-07-28 13:30

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AD',
            fields=[
                ('nom', models.CharField(max_length=100, primary_key=True, serialize=False, unique=True)),
                ('type', models.CharField(max_length=100)),
                ('description', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Askit',
            fields=[
                ('categorie_complete', models.CharField(max_length=100)),
                ('marque', models.CharField(max_length=100)),
                ('modele', models.CharField(max_length=100)),
                ('code_materiel', models.CharField(max_length=100)),
                ('identifiant_reseau', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('numero_serie', models.CharField(max_length=100)),
                ('adresse_ip', models.CharField(max_length=100)),
                ('memoire', models.FloatField()),
                ('statut', models.CharField(max_length=100)),
                ('utilisateur_principal', models.CharField(max_length=100)),
                ('id_user', models.CharField(max_length=100)),
                ('date_depart_user', models.CharField(max_length=100)),
                ('dernier_login_connexion', models.CharField(max_length=100)),
                ('localisation_dernier_niveau', models.CharField(max_length=100)),
                ('emplacement', models.CharField(max_length=100)),
                ('departement', models.FloatField()),
                ('date_livraison', models.CharField(max_length=100)),
                ('date_premiere_installation', models.CharField(max_length=100)),
                ('date_installation', models.CharField(max_length=100)),
                ('dernier_inventaire_discovery', models.CharField(max_length=100)),
                ('dernier_inventaire_physique', models.CharField(max_length=100)),
                ('date_sortie', models.FloatField()),
                ('commentaire', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Defender',
            fields=[
                ('device_id', models.CharField(max_length=200)),
                ('device_name', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('domain', models.CharField(max_length=100)),
                ('first_seen', models.CharField(max_length=100)),
                ('last_device_update', models.CharField(max_length=100)),
                ('os_platform', models.CharField(max_length=100)),
                ('os_distribution', models.CharField(max_length=100)),
                ('os_version', models.CharField(max_length=100)),
                ('os_build', models.FloatField(null=True)),
                ('windows_10_version', models.CharField(max_length=100)),
                ('tags', models.FloatField(null=True)),
                ('group', models.CharField(max_length=100)),
                ('is_aad_joined', models.BooleanField(default=False)),
                ('device_ips', models.CharField(max_length=2000)),
                ('risk_level', models.CharField(max_length=100)),
                ('exposure_level', models.CharField(max_length=100)),
                ('health_status', models.CharField(max_length=100)),
                ('onboarding_status', models.CharField(max_length=100)),
                ('device_role', models.FloatField(null=True)),
                ('managed_by', models.CharField(max_length=100)),
                ('antivirus_status', models.CharField(max_length=100)),
                ('is_internet_facing', models.FloatField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='SAP',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('doma', models.CharField(max_length=255, verbose_name='DomA')),
                ('division', models.CharField(max_length=255, verbose_name='Div.')),
                ('localisat', models.CharField(max_length=255, verbose_name='Localisat.')),
                ('local', models.CharField(max_length=255, verbose_name='Local')),
                ('immobilis', models.CharField(max_length=255, verbose_name='Immobilis.')),
                ('n_s', models.CharField(max_length=255, verbose_name='NºS.')),
                ('n_regr_immobilisation', models.CharField(max_length=255, verbose_name='N°regr.immo.')),
                ('numero_inventaire', models.CharField(max_length=255, verbose_name="Numéro d'inventaire")),
                ('designation_immobilisatio1', models.CharField(max_length=255, verbose_name="Désignation de l'immobilisatio")),
                ('designation_immobilisatio2', models.CharField(max_length=255, verbose_name="Désignation de l'immobilisatio")),
                ('code_designat', models.CharField(max_length=255, verbose_name='Code désignat.')),
                ('mise_serv', models.CharField(max_length=255, verbose_name='Mise serv.')),
                ('comment_invent', models.CharField(max_length=255, verbose_name='Comment.invent.')),
                ('date_inv', models.DateField(verbose_name='Date inv.')),
                ('numero_serie', models.CharField(max_length=255, null=True, verbose_name='Numéro de série')),
                ('n_immatric', models.CharField(max_length=255, verbose_name="N° d'immatric.")),
                ('n_projet_investissement', models.CharField(max_length=255, verbose_name="N° de projet d'investissement")),
                ('disponibilite', models.CharField(max_length=255, verbose_name='Disponibilité')),
                ('fabricant_immobilisation', models.CharField(max_length=255, verbose_name="Fabricant de l'immobilisation")),
                ('fournisseur1', models.CharField(max_length=255, verbose_name='Fourn.')),
                ('fournisseur2', models.CharField(max_length=255, verbose_name='Fournisseur')),
                ('quantite', models.CharField(max_length=255, verbose_name='Quantité')),
                ('uq', models.CharField(max_length=255, verbose_name='UQ')),
                ('compte_cap', models.CharField(max_length=255, verbose_name='Compte CAP')),
                ('cat_immo', models.CharField(max_length=255, verbose_name='Cat.immo')),
                ('centre', models.CharField(max_length=255, verbose_name='Centre')),
                ('val_acq_fin_ex', models.CharField(max_length=255, verbose_name='ValAcqFinEx')),
                ('dev_val_acq_fin_ex', models.CharField(max_length=255, verbose_name='Dev.')),
                ('amortissement_fin_ex', models.CharField(max_length=255, verbose_name='Amo.fin.ex.')),
                ('dev_amortissement_fin_ex', models.CharField(max_length=255, verbose_name='Dev.')),
                ('val_cpt_fin_ex', models.CharField(max_length=255, verbose_name='ValCptFinEx')),
                ('dev_val_cpt_fin_ex', models.CharField(max_length=255, verbose_name='Dev.')),
                ('mise_hs', models.CharField(max_length=255, verbose_name='Mise h.s.')),
                ('immo_d_orig', models.CharField(max_length=255, verbose_name="Immo.d'orig.")),
                ('n_s_iec', models.CharField(max_length=255, verbose_name='N°S. IEC')),
                ('mo', models.CharField(max_length=255, verbose_name='Mo')),
                ('valeur_d_origine', models.CharField(max_length=255, verbose_name="Valeur d'origine")),
                ('dev_valeur_d_origine', models.CharField(max_length=255, verbose_name='Dev.')),
                ('valeur_man_patr', models.CharField(max_length=255, verbose_name='Valeur man. patr.')),
                ('dev_valeur_man_patr', models.CharField(max_length=255, verbose_name='Dev.')),
                ('cod_am', models.CharField(max_length=255, verbose_name='CodAm')),
                ('ut', models.CharField(max_length=255, verbose_name='Ut.')),
                ('per', models.CharField(max_length=255, verbose_name='Pér')),
                ('debut_ad', models.DateField(verbose_name='Début AD')),
            ],
        ),
        migrations.CreateModel(
            name='Sentinels',
            fields=[
                ('endpoint_name', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('site', models.CharField(max_length=100)),
                ('last_logged_in_user', models.CharField(max_length=100)),
                ('os_username', models.FloatField()),
                ('group', models.CharField(max_length=100)),
                ('tags', models.CharField(max_length=100)),
                ('domain', models.CharField(max_length=100)),
                ('account', models.CharField(max_length=100)),
                ('console_visible_ip', models.CharField(max_length=100)),
                ('agent_version', models.CharField(max_length=100)),
                ('serial_number', models.CharField(max_length=100)),
                ('last_active', models.CharField(max_length=100)),
                ('subscribed_on', models.CharField(max_length=100)),
                ('health_status', models.CharField(max_length=100)),
                ('device_type', models.CharField(max_length=100)),
                ('model_name', models.CharField(max_length=100)),
                ('os', models.CharField(max_length=100)),
                ('os_version', models.CharField(max_length=100)),
                ('architecture', models.CharField(max_length=100)),
                ('memory', models.CharField(max_length=100)),
                ('cpu_count', models.IntegerField()),
                ('cpu_type', models.CharField(max_length=100)),
                ('core_count', models.IntegerField()),
                ('management_connectivity', models.CharField(max_length=100)),
                ('network_status', models.CharField(max_length=100)),
                ('update_status', models.CharField(max_length=100)),
                ('scan_status', models.CharField(max_length=100)),
                ('mac_addresses', models.CharField(max_length=900)),
                ('ip_addresses', models.CharField(max_length=2000)),
                ('last_reported_ip', models.CharField(max_length=400)),
                ('pending_uninstall', models.CharField(max_length=100)),
                ('disk_encryption', models.CharField(max_length=100)),
                ('vulnerability_status', models.CharField(max_length=100)),
                ('agent_uuid', models.CharField(max_length=100)),
                ('agent_id', models.CharField(max_length=100)),
                ('customer_identifier', models.FloatField()),
                ('console_migration_status', models.FloatField()),
                ('locations', models.CharField(max_length=100)),
                ('operational_state', models.CharField(max_length=100)),
                ('operational_state_expiration', models.CharField(max_length=100)),
                ('last_reboot_date', models.CharField(max_length=100)),
                ('installer_type', models.CharField(max_length=100)),
                ('reboot_required_due_to_threat', models.CharField(max_length=100)),
                ('user_action_required', models.CharField(max_length=100)),
                ('remote_profiling_state', models.CharField(max_length=100)),
                ('remote_profiling_expiration', models.FloatField()),
                ('storage_type', models.FloatField()),
                ('storage_name', models.FloatField()),
                ('cloud_account', models.FloatField()),
                ('cloud_location', models.FloatField()),
                ('cloud_network', models.FloatField()),
                ('cloud_image', models.FloatField()),
                ('cloud_tags', models.FloatField()),
                ('cloud_instance_size', models.FloatField()),
                ('cloud_instance_id', models.FloatField()),
                ('cloud_security_group', models.FloatField()),
                ('cluster_name', models.FloatField()),
                ('k8s_type', models.FloatField()),
                ('k8s_version', models.FloatField()),
                ('agent_namespace', models.FloatField()),
                ('agent_pod_name', models.FloatField()),
                ('k8s_node_name', models.FloatField()),
                ('k8s_node_labels', models.FloatField()),
                ('is_uninstalled', models.CharField(max_length=100)),
                ('decommissioned_at', models.FloatField()),
            ],
        ),
        migrations.CreateModel(
            name='Sophos',
            fields=[
                ('health_status', models.CharField(max_length=200)),
                ('name', models.CharField(max_length=200, primary_key=True, serialize=False)),
                ('ip', models.CharField(max_length=200)),
                ('os', models.CharField(max_length=200)),
                ('protection', models.CharField(max_length=200)),
                ('last_user', models.CharField(max_length=200)),
                ('last_active', models.CharField(max_length=200)),
                ('computer_group', models.CharField(max_length=200)),
                ('tamper_protection', models.CharField(max_length=200)),
            ],
        ),
    ]
