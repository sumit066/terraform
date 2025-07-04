resource "azurerm_windows_function_app" "wfunc" {
  name                                           = var.name
  location                                       = var.location
  resource_group_name                            = var.resource_group_name
  service_plan_id                                = var.service_plan_id
  builtin_logging_enabled                        = var.builtin_logging_enabled
  client_certificate_enabled                     = var.client_certificate_enabled
  client_certificate_mode                        = var.client_certificate_mode
  client_certificate_exclusion_paths             = var.client_certificate_exclusion_paths
  content_share_force_disabled                   = var.content_share_force_disabled
  daily_memory_time_quota                        = var.daily_memory_time_quota
  enabled                                        = var.enabled
  ftp_publish_basic_authentication_enabled       = var.ftp_publish_basic_authentication_enabled
  functions_extension_version                    = var.functions_extension_version
  https_only                                     = var.https_only
  public_network_access_enabled                  = var.public_network_access_enabled
  key_vault_reference_identity_id                = var.key_vault_reference_identity_id
  storage_account_access_key                     = var.storage_uses_managed_identity == null ? var.storage_account_access_key : null
  storage_account_name                           = var.storage_account_name
  storage_uses_managed_identity                  = var.storage_account_access_key == null ? var.storage_uses_managed_identity : null
  storage_key_vault_secret_id                    = var.storage_key_vault_secret_id
  tags                                           = var.tags
  virtual_network_subnet_id                      = var.virtual_network_subnet_id
  webdeploy_publish_basic_authentication_enabled = var.webdeploy_publish_basic_authentication_enabled
  zip_deploy_file                                = var.zip_deploy_file
  app_settings                                   = var.app_settings

  dynamic "auth_settings" {
    for_each = var.auth_settings != null ? [var.auth_settings] : []
    content {
      enabled                        = auth_settings.value.enabled
      additional_login_parameters    = auth_settings.value.additional_login_parameters
      allowed_external_redirect_urls = auth_settings.value.allowed_external_redirect_urls
      default_provider               = auth_settings.value.default_provider
      issuer                         = auth_settings.value.issuer
      runtime_version                = auth_settings.value.runtime_version
      token_refresh_extension_hours  = auth_settings.value.token_refresh_extension_hours
      token_store_enabled            = auth_settings.value.token_store_enabled
      unauthenticated_client_action  = auth_settings.value.unauthenticated_client_action
      dynamic "active_directory" {
        for_each = auth_settings.value.active_directory != null ? [auth_settings.value.active_directory] : []
        content {
          client_id                  = active_directory.value.client_id
          client_secret              = active_directory.value.client_secret
          client_secret_setting_name = active_directory.value.client_secret_setting_name
          allowed_audiences          = active_directory.value.allowed_audiences
        }
      }
      dynamic "facebook" {
        for_each = auth_settings.value.facebook != null ? [auth_settings.value.facebook] : []
        content {
          app_id                  = facebook.value.app_id
          app_secret              = facebook.value.app_secret
          app_secret_setting_name = facebook.value.app_secret_setting_name
          oauth_scopes            = facebook.value.oauth_scopes
        }
      }
      dynamic "github" {
        for_each = auth_settings.value.github != null ? [auth_settings.value.github] : []
        content {
          client_id                  = github.value.client_id
          client_secret              = github.value.client_secret
          client_secret_setting_name = github.value.client_secret_setting_name
          oauth_scopes               = github.value.oauth_scopes
        }
      }
      dynamic "google" {
        for_each = auth_settings.value.google != null ? [auth_settings.value.google] : []
        content {
          client_id                  = google.value.client_id
          client_secret              = google.value.client_secret
          client_secret_setting_name = google.value.client_secret_setting_name
          oauth_scopes               = google.value.oauth_scopes
        }
      }
      dynamic "microsoft" {
        for_each = auth_settings.value.microsoft != null ? [auth_settings.value.microsoft] : []
        content {
          client_id                  = microsoft.value.client_id
          client_secret              = microsoft.value.client_secret
          client_secret_setting_name = microsoft.value.client_secret_setting_name
          oauth_scopes               = microsoft.value.oauth_scopes
        }
      }
      dynamic "twitter" {
        for_each = auth_settings.value.twitter != null ? [auth_settings.value.twitter] : []
        content {
          consumer_key                 = twitter.value.consumer_key
          consumer_secret              = twitter.value.consumer_secret
          consumer_secret_setting_name = twitter.value.consumer_secret_setting_name
        }
      }
    }
  }
  dynamic "auth_settings_v2" {
    for_each = var.auth_settings_v2 != null ? [var.auth_settings_v2] : []
    content {
      auth_enabled                            = auth_settings_v2.value.auth_enabled
      runtime_version                         = auth_settings_v2.value.runtime_version
      config_file_path                        = auth_settings_v2.value.config_file_path
      require_authentication                  = auth_settings_v2.value.require_authentication
      unauthenticated_action                  = auth_settings_v2.value.unauthenticated_action
      default_provider                        = auth_settings_v2.value.default_provider
      excluded_paths                          = auth_settings_v2.value.excluded_paths
      require_https                           = auth_settings_v2.value.require_https
      http_route_api_prefix                   = auth_settings_v2.value.http_route_api_prefix
      forward_proxy_convention                = auth_settings_v2.value.forward_proxy_convention
      forward_proxy_custom_host_header_name   = auth_settings_v2.value.forward_proxy_custom_host_header_name
      forward_proxy_custom_scheme_header_name = auth_settings_v2.value.forward_proxy_custom_scheme_header_name
      dynamic "apple_v2" {
        for_each = auth_settings_v2.value.apple_v2 != null ? [auth_settings_v2.value.apple_v2] : []
        content {
          client_id                  = apple_v2.value.client_id
          client_secret_setting_name = apple_v2.value.client_secret_setting_name
          login_scopes               = apple_v2.value.login_scopes
        }
      }
      dynamic "active_directory_v2" {
        for_each = auth_settings_v2.value.active_directory_v2 != null ? [auth_settings_v2.value.active_directory_v2] : []
        content {
          client_id                            = active_directory_v2.value.client_id
          tenant_auth_endpoint                 = active_directory_v2.value.tenant_auth_endpoint
          client_secret_setting_name           = active_directory_v2.value.client_secret_setting_name
          client_secret_certificate_thumbprint = active_directory_v2.value.client_secret_certificate_thumbprint
          jwt_allowed_groups                   = active_directory_v2.value.jwt_allowed_groups
          jwt_allowed_client_applications      = active_directory_v2.value.jwt_allowed_client_applications
          www_authentication_disabled          = active_directory_v2.value.www_authentication_disabled
          allowed_groups                       = active_directory_v2.value.allowed_groups
          allowed_identities                   = active_directory_v2.value.allowed_identities
          allowed_applications                 = active_directory_v2.value.allowed_applications
          login_parameters                     = active_directory_v2.value.login_parameters
          allowed_audiences                    = active_directory_v2.value.allowed_audiences
        }
      }
      dynamic "azure_static_web_app_v2" {
        for_each = auth_settings_v2.value.azure_static_web_app_v2 != null ? [auth_settings_v2.value.azure_static_web_app_v2] : []
        content {
          client_id = azure_static_web_app_v2.value.client_id
        }
      }
      dynamic "custom_oidc_v2" {
        for_each = auth_settings_v2.value.custom_oidc_v2 != null ? auth_settings_v2.value.custom_oidc_v2 : []
        content {
          name                          = custom_oidc_v2.value.name
          client_id                     = custom_oidc_v2.value.client_id
          openid_configuration_endpoint = custom_oidc_v2.value.openid_configuration_endpoint
          name_claim_type               = custom_oidc_v2.value.name_claim_type
          scopes                        = custom_oidc_v2.value.scopes
          client_credential_method      = custom_oidc_v2.value.client_credential_method
          client_secret_setting_name    = custom_oidc_v2.value.client_secret_setting_name
          authorisation_endpoint        = custom_oidc_v2.value.authorisation_endpoint
          token_endpoint                = custom_oidc_v2.value.token_endpoint
          issuer_endpoint               = custom_oidc_v2.value.issuer_endpoint
          certification_uri             = custom_oidc_v2.value.certification_uri
        }
      }
      dynamic "facebook_v2" {
        for_each = auth_settings_v2.value.facebook_v2 != null ? [auth_settings_v2.value.facebook_v2] : []
        content {
          app_id                  = facebook_v2.value.app_id
          app_secret_setting_name = facebook_v2.value.app_secret_setting_name
          graph_api_version       = facebook_v2.value.graph_api_version
          login_scopes            = facebook_v2.value.login_scopes
        }
      }
      dynamic "github_v2" {
        for_each = auth_settings_v2.value.github_v2 != null ? [auth_settings_v2.value.github_v2] : []
        content {
          client_id                  = github_v2.value.client_id
          client_secret_setting_name = github_v2.value.client_secret_setting_name
          login_scopes               = github_v2.value.login_scopes
        }
      }
      dynamic "google_v2" {
        for_each = auth_settings_v2.value.google_v2 != null ? [auth_settings_v2.value.google_v2] : []
        content {
          client_id                  = google_v2.value.client_id
          client_secret_setting_name = google_v2.value.client_secret_setting_name
          allowed_audiences          = google_v2.value.allowed_audiences
          login_scopes               = google_v2.value.login_scopes
        }
      }
      dynamic "microsoft_v2" {
        for_each = auth_settings_v2.value.microsoft_v2 != null ? [auth_settings_v2.value.microsoft_v2] : []
        content {
          client_id                  = microsoft_v2.value.client_id
          client_secret_setting_name = microsoft_v2.value.client_secret_setting_name
          allowed_audiences          = microsoft_v2.value.allowed_audiences
          login_scopes               = microsoft_v2.value.login_scopes
        }
      }
      dynamic "twitter_v2" {
        for_each = auth_settings_v2.value.twitter_v2 != null ? [auth_settings_v2.value.twitter_v2] : []
        content {
          consumer_key                 = twitter_v2.value.consumer_key
          consumer_secret_setting_name = twitter_v2.value.consumer_secret_setting_name
        }
      }
      login {
        logout_endpoint                   = auth_settings_v2.value.login.logout_endpoint
        token_store_enabled               = auth_settings_v2.value.login.token_store_enabled
        token_refresh_extension_time      = auth_settings_v2.value.login.token_refresh_extension_time
        token_store_path                  = auth_settings_v2.value.login.token_store_path
        token_store_sas_setting_name      = auth_settings_v2.value.login.token_store_sas_setting_name
        preserve_url_fragments_for_logins = auth_settings_v2.value.login.preserve_url_fragments_for_logins
        allowed_external_redirect_urls    = auth_settings_v2.value.login.allowed_external_redirect_urls
        cookie_expiration_convention      = auth_settings_v2.value.login.cookie_expiration_convention
        cookie_expiration_time            = auth_settings_v2.value.login.cookie_expiration_time
        validate_nonce                    = auth_settings_v2.value.login.validate_nonce
        nonce_expiration_time             = auth_settings_v2.value.login.nonce_expiration_time
      }
    }
  }
  dynamic "backup" {
    for_each = var.backup != null ? var.backup : []
    content {
      name                = backup.value.name
      storage_account_url = backup.value.storage_account_url
      enabled             = backup.value.enabled

      schedule {
        frequency_interval       = backup.value.schedule.frequency_interval
        frequency_unit           = backup.value.schedule.frequency_unit
        keep_at_least_one_backup = backup.value.schedule.keep_at_least_one_backup
        retention_period_days    = backup.value.schedule.retention_period_days
        start_time               = backup.value.schedule.start_time
      }
    }
  }
  dynamic "connection_string" {
    for_each = var.connection_strings != null ? var.connection_strings : []
    content {
      name  = connection_string.value.name
      type  = connection_string.value.type
      value = connection_string.value.value
    }
  }
  dynamic "identity" {
    for_each = var.identity != null ? [var.identity] : []
    content {
      type         = identity.value.type
      identity_ids = identity.value.identity_ids
    }
  }
  site_config {
    always_on                              = var.site_config.always_on
    ftps_state                             = var.site_config.ftps_state
    http2_enabled                          = var.site_config.http2_enabled
    minimum_tls_version                    = var.site_config.minimum_tls_version
    api_definition_url                     = var.site_config.api_definition_url
    api_management_api_id                  = var.site_config.api_management_api_id
    app_command_line                       = var.site_config.app_command_line
    app_scale_limit                        = var.site_config.app_scale_limit
    application_insights_key               = var.site_config.application_insights_key
    application_insights_connection_string = var.site_config.application_insights_connection_string
    default_documents                      = var.site_config.default_documents
    elastic_instance_minimum               = var.site_config.elastic_instance_minimum
    health_check_path                      = var.site_config.health_check_path
    health_check_eviction_time_in_min      = var.site_config.health_check_eviction_time_in_min
    ip_restriction_default_action          = var.site_config.ip_restriction_default_action
    load_balancing_mode                    = var.site_config.load_balancing_mode
    managed_pipeline_mode                  = var.site_config.managed_pipeline_mode
    pre_warmed_instance_count              = var.site_config.pre_warmed_instance_count
    remote_debugging_enabled               = var.site_config.remote_debugging_enabled
    remote_debugging_version               = var.site_config.remote_debugging_version
    runtime_scale_monitoring_enabled       = var.site_config.runtime_scale_monitoring_enabled
    scm_ip_restriction_default_action      = var.site_config.scm_ip_restriction_default_action
    scm_minimum_tls_version                = var.site_config.scm_minimum_tls_version
    scm_use_main_ip_restriction            = var.site_config.scm_use_main_ip_restriction
    use_32_bit_worker                      = var.site_config.use_32_bit_worker
    vnet_route_all_enabled                 = var.site_config.vnet_route_all_enabled
    websockets_enabled                     = var.site_config.websockets_enabled
    worker_count                           = var.site_config.worker_count
    dynamic "cors" {
      for_each = var.site_config.cors != null ? [var.site_config.cors] : []
      content {
        allowed_origins     = cors.value.allowed_origins
        support_credentials = cors.value.support_credentials
      }
    }
    dynamic "ip_restriction" {
      for_each = var.site_config.ip_restriction != null ? var.site_config.ip_restriction : []
      content {
        name                      = ip_restriction.value.name
        action                    = ip_restriction.value.action
        ip_address                = ip_restriction.value.ip_address
        service_tag               = ip_restriction.value.service_tag
        virtual_network_subnet_id = ip_restriction.value.virtual_network_subnet_id
        priority                  = ip_restriction.value.priority
        description               = ip_restriction.value.description

        dynamic "headers" {
          for_each = ip_restriction.value.headers != null ? [ip_restriction.value.headers] : []
          content {
            x_azure_fdid      = headers.value.x_azure_fdid
            x_fd_health_probe = headers.value.x_fd_health_probe
            x_forwarded_for   = headers.value.x_forwarded_for
            x_forwarded_host  = headers.value.x_forwarded_host
          }
        }
      }
    }
    dynamic "app_service_logs" {
      for_each = var.site_config.app_service_logs != null ? [var.site_config.app_service_logs] : []
      content {
        disk_quota_mb         = app_service_logs.value.disk_quota_mb
        retention_period_days = app_service_logs.value.retention_period_days
      }
    }
    dynamic "application_stack" {
      for_each = var.site_config.application_stack != null ? [var.site_config.application_stack] : []
      content {
        dotnet_version              = application_stack.value.dotnet_version
        use_dotnet_isolated_runtime = application_stack.value.use_dotnet_isolated_runtime
        java_version                = application_stack.value.java_version
        node_version                = application_stack.value.node_version
        powershell_core_version     = application_stack.value.powershell_core_version
        use_custom_runtime          = application_stack.value.use_custom_runtime
      }
    }
    dynamic "scm_ip_restriction" {
      for_each = var.site_config.scm_ip_restriction != null ? var.site_config.scm_ip_restriction : []
      content {
        name                      = scm_ip_restriction.value.name
        action                    = scm_ip_restriction.value.action
        ip_address                = scm_ip_restriction.value.ip_address
        service_tag               = scm_ip_restriction.value.service_tag
        virtual_network_subnet_id = scm_ip_restriction.value.virtual_network_subnet_id
        priority                  = scm_ip_restriction.value.priority
        description               = scm_ip_restriction.value.description

        dynamic "headers" {
          for_each = scm_ip_restriction.value.headers != null ? [scm_ip_restriction.value.headers] : []
          content {
            x_azure_fdid      = headers.value.x_azure_fdid
            x_fd_health_probe = headers.value.x_fd_health_probe
            x_forwarded_for   = headers.value.x_forwarded_for
            x_forwarded_host  = headers.value.x_forwarded_host
          }
        }
      }
    }
  }

  dynamic "sticky_settings" {
    for_each = var.sticky_settings != null ? [var.sticky_settings] : []
    content {
      app_setting_names       = sticky_settings.value.app_setting_names
      connection_string_names = sticky_settings.value.connection_string_names
    }
  }
  dynamic "storage_account" {
    for_each = var.storage_account != null ? var.storage_account : []
    content {
      name         = storage_account.value.name
      type         = storage_account.value.type
      account_name = storage_account.value.account_name
      access_key   = storage_account.value.access_key
      share_name   = storage_account.value.share_name
      mount_path   = storage_account.value.mount_path
    }
  }

  lifecycle {
    ignore_changes = [name]
  }
}
