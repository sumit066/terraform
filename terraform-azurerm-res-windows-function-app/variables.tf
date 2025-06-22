
variable "name" {
  type        = string
  description = "The name which should be used for this Windows Function App. Changing this forces a new Windows Function App to be created. Limit the function name to 32 characters to avoid naming collisions. For more information about Function App naming rule and Host ID Collisions."
}

variable "location" {
  type        = string
  description = "The Azure Region where the Windows Function App should exist. Changing this forces a new Windows Function App to be created."
}

variable "resource_group_name" {
  type        = string
  description = "The name of the Resource Group where the Windows Function App should exist. Changing this forces a new Windows Function App to be created."
}

variable "service_plan_id" {
  type        = string
  description = "The ID of the App Service Plan within which to create this Function App."
}

variable "builtin_logging_enabled" {
  type        = bool
  default     = true
  description = "Should built in logging be enabled. Configures AzureWebJobsDashboard app setting based on the configured storage setting. Defaults to true."
}

variable "client_certificate_enabled" {
  type        = bool
  default     = false
  description = "Should the function app use Client Certificates."
}

variable "client_certificate_mode" {
  type        = string
  default     = "Optional"
  description = "The mode of the Function App's client certificates requirement for incoming requests. Possible values are Required, Optional, and OptionalInteractiveUser. Defaults to Optional."
  validation {
    condition     = contains(["Required", "Optional", "OptionalInteractiveUser"], var.client_certificate_mode)
    error_message = "Invalid `client_certificate_mode`. Must be one of `Required`, `Optional` or `OptionalInteractiveUser`."
  }
}

variable "client_certificate_exclusion_paths" {
  type        = string
  default     = null
  description = "Paths to exclude when using client certificates, separated by ;"
}

variable "content_share_force_disabled" {
  type        = bool
  default     = false
  description = "Should Content Share Settings be disabled. Defaults to false."
}

variable "daily_memory_time_quota" {
  type        = number
  default     = 0
  description = "The amount of memory in gigabyte-seconds that your application is allowed to consume per day. Setting this value only affects function apps under the consumption plan. Defaults to 0."
}

variable "enabled" {
  type        = bool
  default     = true
  description = "Is the Function App enabled? Defaults to true."
}

variable "ftp_publish_basic_authentication_enabled" {
  type        = bool
  default     = true
  description = "Should the default FTP Basic Authentication publishing profile be enabled. Defaults to true."
}

variable "functions_extension_version" {
  type        = string
  default     = "~4"
  description = "The runtime version associated with the Function App. Defaults to ~4."
}

variable "https_only" {
  type        = bool
  default     = false
  description = "Can the Function App only be accessed via HTTPS?. Defaults to false."
}

variable "public_network_access_enabled" {
  type        = bool
  default     = true
  description = "Should public network access be enabled for the Function App. Defaults to true."
}

variable "key_vault_reference_identity_id" {
  type        = string
  default     = null
  description = "he User Assigned Identity ID used for accessing KeyVault secrets. The identity must be assigned to the application in the identity block."
}

variable "storage_account_access_key" {
  type        = string
  default     = null
  sensitive   = true
  description = "Primary access key for the content storage account (if not using managed identity)."
}

variable "storage_account_name" {
  type        = string
  default     = null
  description = "The backend storage account name which will be used by this Function App."
}

variable "storage_uses_managed_identity" {
  type        = bool
  default     = false
  description = "Use managed identity to access the content storage account."
}

variable "storage_key_vault_secret_id" {
  type        = string
  default     = null
  description = "The Key Vault Secret ID, optionally including version, that contains the Connection String to connect to the storage account for this Function App."
}

variable "virtual_network_subnet_id" {
  type        = string
  default     = null
  description = "The subnet id which will be used by this Function App for regional virtual network integration."
}

variable "webdeploy_publish_basic_authentication_enabled" {
  type        = bool
  default     = true
  description = "Should the default WebDeploy Basic Authentication publishing credentials enabled. Defaults to true."
}

variable "zip_deploy_file" {
  type        = string
  default     = null
  description = "The local path and filename of the Zip packaged application to deploy to this Windows Function App."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "A mapping of tags which should be assigned to the Windows Function App."
}

variable "app_settings" {
  type        = map(string)
  default     = {}
  description = "A map of key-value pairs for App Settings and custom values."
}
variable "auth_settings" {
  type = object({
    enabled                        = bool
    additional_login_parameters    = optional(map(string))
    allowed_external_redirect_urls = optional(list(string))
    default_provider               = optional(string)
    issuer                         = optional(string)
    runtime_version                = optional(string)
    token_refresh_extension_hours  = optional(number, 72)
    token_store_enabled            = optional(bool, false)
    unauthenticated_client_action  = optional(string, "RedirectToLoginPage")

    active_directory = optional(object({
      client_id                  = string
      client_secret              = optional(string)
      client_secret_setting_name = optional(string)
      allowed_audiences          = optional(list(string))
    }))

    facebook = optional(object({
      app_id                  = string
      app_secret              = optional(string)
      app_secret_setting_name = optional(string)
      oauth_scopes            = optional(list(string))
    }))

    github = optional(object({
      client_id                  = string
      client_secret              = optional(string)
      client_secret_setting_name = optional(string)
      oauth_scopes               = optional(list(string))
    }))

    google = optional(object({
      client_id                  = string
      client_secret              = optional(string)
      client_secret_setting_name = optional(string)
      oauth_scopes               = optional(list(string))
    }))

    microsoft = optional(object({
      client_id                  = string
      client_secret              = optional(string)
      client_secret_setting_name = optional(string)
      oauth_scopes               = optional(list(string))
    }))

    twitter = optional(object({
      consumer_key                 = string
      consumer_secret              = optional(string)
      consumer_secret_setting_name = optional(string)
    }))
  })
  default     = null
  description = <<DESCRIPTION
(Optional) AuthV1 block for legacy Authentication/Authorization configuration.
- `enabled`                        - Enable or disable authentication/authorization for the app.
- `additional_login_parameters`    - (Optional) A map of key-value pairs to pass as additional login parameters.
- `allowed_external_redirect_urls` - (Optional) List of external URLs to allow as valid redirect destinations.
- `default_provider`               - (Optional) Default identity provider to use when multiple providers are configured.
- `issuer`                         - (Optional) The token issuer URL for custom JWT validation.
- `runtime_version`                - (Optional) Runtime version for the authentication module.
- `token_refresh_extension_hours`  - (Optional) Number of hours after which tokens are refreshed. Defaults to `72`.
- `token_store_enabled`            - (Optional) Enable or disable token storage. Defaults to `false`.
- `unauthenticated_client_action`  - (Optional) Action to take for unauthenticated requests. Defaults to `"RedirectToLoginPage"`.

- `active_directory` - (Optional) Azure Active Directory identity provider block:
  - `client_id`                  - The client ID of the app registered in Azure AD.
  - `client_secret`              - (Optional) The client secret.
  - `client_secret_setting_name` - (Optional) The name of the setting that contains the client secret.
  - `allowed_audiences`          - (Optional) List of allowed token audiences.

- `facebook` - (Optional) Facebook identity provider block:
  - `app_id`                  - The Facebook App ID.
  - `app_secret`              - (Optional) The App secret.
  - `app_secret_setting_name` - (Optional) Name of the App secret setting.
  - `oauth_scopes`            - (Optional) List of OAuth scopes to request.

- `github` - (Optional) GitHub identity provider block:
  - `client_id`                  - GitHub client ID.
  - `client_secret`              - (Optional) GitHub client secret.
  - `client_secret_setting_name` - (Optional) Name of the GitHub client secret setting.
  - `oauth_scopes`               - (Optional) List of OAuth scopes to request.

- `google` - (Optional) Google identity provider block:
  - `client_id`                  - Google client ID.
  - `client_secret`              - (Optional) Google client secret.
  - `client_secret_setting_name` - (Optional) Name of the Google client secret setting.
  - `oauth_scopes`               - (Optional) List of OAuth scopes to request.

- `microsoft` - (Optional) Microsoft identity provider block:
  - `client_id`                  - Microsoft client ID.
  - `client_secret`              - (Optional) Microsoft client secret.
  - `client_secret_setting_name` - (Optional) Name of the Microsoft client secret setting.
  - `oauth_scopes`               - (Optional) List of OAuth scopes to request.

- `twitter` - (Optional) Twitter identity provider block:
  - `consumer_key`                 - Twitter consumer key.
  - `consumer_secret`              - (Optional) Twitter consumer secret.
  - `consumer_secret_setting_name` - (Optional) Name of the Twitter consumer secret setting.
DESCRIPTION
}
variable "auth_settings_v2" {
  type = object({
    auth_enabled                            = optional(bool, false)
    runtime_version                         = optional(string, "~1")
    config_file_path                        = optional(string)
    require_authentication                  = optional(bool)
    unauthenticated_action                  = optional(string, "RedirectToLoginPage")
    default_provider                        = optional(string)
    excluded_paths                          = optional(list(string))
    require_https                           = optional(bool, true)
    http_route_api_prefix                   = optional(string, "/.auth")
    forward_proxy_convention                = optional(string, "NoProxy")
    forward_proxy_custom_host_header_name   = optional(string)
    forward_proxy_custom_scheme_header_name = optional(string)
    apple_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      login_scopes               = optional(list(string))
    }))

    active_directory_v2 = optional(object({
      client_id                            = string
      tenant_auth_endpoint                 = string
      client_secret_setting_name           = optional(string)
      client_secret_certificate_thumbprint = optional(string)
      jwt_allowed_groups                   = optional(list(string))
      jwt_allowed_client_applications      = optional(list(string))
      www_authentication_disabled          = optional(bool, false)
      allowed_groups                       = optional(list(string))
      allowed_identities                   = optional(list(string))
      allowed_applications                 = optional(list(string))
      login_parameters                     = optional(map(string))
      allowed_audiences                    = optional(list(string))
    }))

    azure_static_web_app_v2 = optional(object({
      client_id = string
    }))

    custom_oidc_v2 = optional(list(object({
      name                          = string
      client_id                     = string
      openid_configuration_endpoint = string
      name_claim_type               = optional(string)
      scopes                        = optional(list(string))
      client_credential_method      = optional(string)
      client_secret_setting_name    = optional(string)
      authorisation_endpoint        = optional(string)
      token_endpoint                = optional(string)
      issuer_endpoint               = optional(string)
      certification_uri             = optional(string)
    })))

    facebook_v2 = optional(object({
      app_id                  = string
      app_secret_setting_name = string
      graph_api_version       = optional(string)
      login_scopes            = optional(list(string))
    }))

    github_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      login_scopes               = optional(list(string))
    }))

    google_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      allowed_audiences          = optional(list(string))
      login_scopes               = optional(list(string))
    }))

    microsoft_v2 = optional(object({
      client_id                  = string
      client_secret_setting_name = string
      allowed_audiences          = optional(list(string))
      login_scopes               = optional(list(string))
    }))

    twitter_v2 = optional(object({
      consumer_key                 = string
      consumer_secret_setting_name = string
    }))

    login = object({
      logout_endpoint                   = optional(string)
      token_store_enabled               = optional(bool, false)
      token_refresh_extension_time      = optional(number, 72)
      token_store_path                  = optional(string)
      token_store_sas_setting_name      = optional(string)
      preserve_url_fragments_for_logins = optional(bool, false)
      allowed_external_redirect_urls    = optional(list(string))
      cookie_expiration_convention      = optional(string, "FixedTime")
      cookie_expiration_time            = optional(string, "08:00:00")
      validate_nonce                    = optional(bool, true)
      nonce_expiration_time             = optional(string, "00:05:00")
    })
  })
  default     = null
  description = <<DESCRIPTION
`auth_settings_v2` block for configuring App Service authentication and authorization (Easy Auth) using the latest version (v2). Recommended for new applications. Omit or set to `null` to disable authentication.

General Settings:
- `auth_enabled` - (Optional) Enables authentication/authorization feature. Defaults to `false`.
- `runtime_version` - (Optional) Runtime version of the authentication module. Defaults to `"~1"`.
- `config_file_path` - (Optional) Path to the authentication configuration file.
- `require_authentication` - (Optional) Whether authentication is required for all requests.
- `unauthenticated_action` - (Optional) Action to take for unauthenticated requests. Possible values: `RedirectToLoginPage`, `AllowAnonymous`. Defaults to `"RedirectToLoginPage"`.
- `default_provider` - (Optional) The default authentication provider to use.
- `excluded_paths` - (Optional) List of paths that are excluded from authentication.
- `require_https` - (Optional) Require HTTPS for all requests. Defaults to `true`.
- `http_route_api_prefix` - (Optional) API route prefix used by the built-in auth system. Defaults to `"/.auth"`.
- `forward_proxy_convention` - (Optional) Convention used when forwarding headers. Possible values: `NoProxy`, `Standard`, `CustomHeader`. Defaults to `"NoProxy"`.
- `forward_proxy_custom_host_header_name` - (Optional) Custom header for the host name when `forward_proxy_convention` is `CustomHeader`.
- `forward_proxy_custom_scheme_header_name` - (Optional) Custom header for the scheme when `forward_proxy_convention` is `CustomHeader`.

Identity Providers:
- `apple_v2` - (Optional) Apple identity provider configuration.
  - `client_id` - Apple client ID.
  - `client_secret_setting_name` - Key Vault secret name containing the client secret.
  - `login_scopes` - (Optional) List of scopes for login.

- `active_directory_v2` - (Optional) Azure Active Directory (v2) configuration.
  - `client_id` - AAD app client ID.
  - `tenant_auth_endpoint` - AAD tenant authorization endpoint.
  - `client_secret_setting_name` - (Optional) Name of the app secret in Key Vault.
  - `client_secret_certificate_thumbprint` - (Optional) Certificate thumbprint for authentication.
  - `jwt_allowed_groups` - (Optional) List of allowed JWT groups.
  - `jwt_allowed_client_applications` - (Optional) Allowed client app IDs.
  - `www_authentication_disabled` - (Optional) Disable browser-based login. Defaults to `false`.
  - `allowed_groups` - (Optional) List of allowed AAD groups.
  - `allowed_identities` - (Optional) List of allowed identities.
  - `allowed_applications` - (Optional) List of allowed applications.
  - `login_parameters` - (Optional) Custom query parameters to include in login URL.
  - `allowed_audiences` - (Optional) List of JWT audiences accepted.

- `azure_static_web_app_v2` - (Optional) Identity provider for Azure Static Web Apps.
  - `client_id` - Static Web App client ID.

- `custom_oidc_v2` - (Optional) List of custom OpenID Connect identity providers.
  - `name` - Display name of the provider.
  - `client_id` - Client ID.
  - `openid_configuration_endpoint` - OIDC discovery endpoint.
  - `name_claim_type` - (Optional) Name claim type to use from ID token.
  - `scopes` - (Optional) List of scopes.
  - `client_credential_method` - (Optional) Credential method: `ClientSecretPost`, etc.
  - `client_secret_setting_name` - (Optional) Secret setting name.
  - `authorisation_endpoint` - (Optional) Explicit auth endpoint.
  - `token_endpoint` - (Optional) Explicit token endpoint.
  - `issuer_endpoint` - (Optional) Explicit issuer endpoint.
  - `certification_uri` - (Optional) Certificate discovery URI.

- `facebook_v2` - (Optional) Facebook identity provider configuration.
  - `app_id` - Facebook app ID.
  - `app_secret_setting_name` - Secret name for the app secret.
  - `graph_api_version` - (Optional) Facebook Graph API version.
  - `login_scopes` - (Optional) List of login scopes.

- `github_v2` - (Optional) GitHub identity provider configuration.
  - `client_id` - GitHub OAuth app client ID.
  - `client_secret_setting_name` - Secret name for GitHub app secret.
  - `login_scopes` - (Optional) List of login scopes.

- `google_v2` - (Optional) Google identity provider configuration.
  - `client_id` - Google client ID.
  - `client_secret_setting_name` - Secret name for client secret.
  - `allowed_audiences` - (Optional) List of allowed audiences.
  - `login_scopes` - (Optional) List of login scopes.

- `microsoft_v2` - (Optional) Microsoft identity provider configuration.
  - `client_id` - Microsoft app client ID.
  - `client_secret_setting_name` - Secret name for app secret.
  - `allowed_audiences` - (Optional) List of allowed audiences.
  - `login_scopes` - (Optional) List of login scopes.

- `twitter_v2` - (Optional) Twitter identity provider configuration.
  - `consumer_key` - Twitter app consumer key.
  - `consumer_secret_setting_name` - Secret name for the consumer secret.

- `login` - (Required) Controls session management and login/logout behavior.
  - `logout_endpoint` - (Optional) Custom logout endpoint.
  - `token_store_enabled` - (Optional) Store tokens in file system. Defaults to `false`.
  - `token_refresh_extension_time` - (Optional) Additional time in hours before token expiration. Defaults to `72`.
  - `token_store_path` - (Optional) Path to store tokens.
  - `token_store_sas_setting_name` - (Optional) SAS token setting name for token storage.
  - `preserve_url_fragments_for_logins` - (Optional) Preserve URL fragments during login redirects. Defaults to `false`.
  - `allowed_external_redirect_urls` - (Optional) List of valid external redirect URLs.
  - `cookie_expiration_convention` - (Optional) Cookie expiration style. Options: `FixedTime`, `IdentityProviderDerived`. Defaults to `"FixedTime"`.
  - `cookie_expiration_time` - (Optional) Duration of cookie validity in `hh:mm:ss`. Defaults to `"08:00:00"`.
  - `validate_nonce` - (Optional) Validate nonce during login. Defaults to `true`.
  - `nonce_expiration_time` - (Optional) Expiry for nonce tokens in `hh:mm:ss`. Defaults to `"00:05:00"`.

DESCRIPTION
}
variable "backup" {
  type = list(object({
    name                = string
    storage_account_url = string
    enabled             = optional(bool, true)

    schedule = object({
      frequency_interval       = number
      frequency_unit           = string
      keep_at_least_one_backup = optional(bool, false)
      retention_period_days    = optional(number, 30)
      start_time               = optional(string)
    })
  }))
  default     = []
  description = <<DESCRIPTION
(Optional) Zero or more backup jobs for the Function App.
- `name`                - Name of the backup job.
- `storage_account_url` - URL of the storage account used for backups.
- `enabled`             - (Optional) Whether the backup is enabled. Defaults to `true`.

- `schedule` - Required schedule configuration:
  - `frequency_interval`       - Frequency interval for backups.
  - `frequency_unit`           - Unit of backup frequency (e.g., Day, Hour).
  - `keep_at_least_one_backup` - (Optional) Ensure at least one backup is retained. Defaults to `false`.
  - `retention_period_days`    - (Optional) Retention period in days. Defaults to `30`.
  - `start_time`               - (Optional) Time to start the backup.
DESCRIPTION
}

variable "connection_strings" {
  type = list(object({
    name  = string
    type  = string
    value = string
  }))
  default     = []
  description = <<DESCRIPTION
(Optional) List of connection strings exposed to the Function runtime.
- `name`  - Name of the connection string.
- `type`  - Type of connection (e.g., SQLServer, Custom).
- `value` - The actual connection string value.
DESCRIPTION
}
variable "identity" {
  type = object({
    type         = string
    identity_ids = optional(list(string))
  })
  default     = null
  description = <<DESCRIPTION
(Optional) Managed Service Identity configuration for the Function App.
- `type`         - Identity type (SystemAssigned or UserAssigned).
- `identity_ids` - (Optional) List of user-assigned identity resource IDs.
DESCRIPTION
}
variable "site_config" {
  type = object({
    always_on                              = optional(bool, false)
    api_definition_url                     = optional(string)
    api_management_api_id                  = optional(string)
    app_command_line                       = optional(string)
    app_scale_limit                        = optional(number)
    application_insights_key               = optional(string)
    application_insights_connection_string = optional(string)
    default_documents                      = optional(list(string))
    elastic_instance_minimum               = optional(number)
    ftps_state                             = optional(string, "Disabled")
    health_check_path                      = optional(string)
    health_check_eviction_time_in_min      = optional(number)
    http2_enabled                          = optional(bool, false)
    ip_restriction_default_action          = optional(string, "Allow")
    load_balancing_mode                    = optional(string)
    managed_pipeline_mode                  = optional(string, "Integrated")
    minimum_tls_version                    = optional(string, "1.2")
    pre_warmed_instance_count              = optional(number)
    remote_debugging_enabled               = optional(bool, false)
    remote_debugging_version               = optional(string, "VS2022")
    runtime_scale_monitoring_enabled       = optional(bool)
    scm_ip_restriction_default_action      = optional(string, "Allow")
    scm_minimum_tls_version                = optional(string, "1.2")
    scm_use_main_ip_restriction            = optional(bool)
    use_32_bit_worker                      = optional(bool, true)
    vnet_route_all_enabled                 = optional(bool, false)
    websockets_enabled                     = optional(bool, false)
    worker_count                           = optional(number)

    cors = optional(object({
      allowed_origins     = optional(list(string))
      support_credentials = optional(bool, false)
    }))

    ip_restriction = optional(list(object({
      name                      = optional(string)
      action                    = optional(string, "Allow")
      ip_address                = optional(string)
      service_tag               = optional(string)
      virtual_network_subnet_id = optional(string)
      priority                  = optional(number, 65000)
      description               = optional(string)
      headers = optional(object({
        x_azure_fdid      = optional(list(string))
        x_fd_health_probe = optional(string)
        x_forwarded_for   = optional(list(string))
        x_forwarded_host  = optional(list(string))
      }))
    })))

    scm_ip_restriction = optional(list(object({
      name                      = optional(string)
      action                    = optional(string, "Allow")
      ip_address                = optional(string)
      service_tag               = optional(string)
      virtual_network_subnet_id = optional(string)
      priority                  = optional(number, 65000)
      description               = optional(string)
      headers = optional(object({
        x_azure_fdid      = optional(list(string))
        x_fd_health_probe = optional(string)
        x_forwarded_for   = optional(list(string))
        x_forwarded_host  = optional(list(string))
      }))
    })))

    app_service_logs = optional(object({
      disk_quota_mb         = optional(number, 35)
      retention_period_days = optional(number, 7)
    }))

    application_stack = optional(object({
      dotnet_version              = optional(string)
      use_dotnet_isolated_runtime = optional(bool)
      java_version                = optional(string)
      node_version                = optional(string)
      powershell_core_version     = optional(string)
      use_custom_runtime          = optional(bool)
    }))
  })

  default = {}

  description = <<DESCRIPTION
Configuration block for advanced `site_config` settings of the Windows Function App.

- `always_on` - (Optional) Whether the app is always active. Defaults to `false`.
- `api_definition_url` - (Optional) URL of the API definition (Swagger).
- `api_management_api_id` - (Optional) API Management API ID for integration.
- `app_command_line` - (Optional) App-specific startup command.
- `app_scale_limit` - (Optional) Maximum number of scale-out instances.
- `application_insights_key` - (Optional) Instrumentation key for Application Insights.
- `application_insights_connection_string` - (Optional) Full connection string for Application Insights.
- `default_documents` - (Optional) List of default documents for the app.
- `elastic_instance_minimum` - (Optional) Minimum number of elastic premium instances.
- `ftps_state` - (Optional) State of FTP/FTPS service. Defaults to `"Disabled"`.
- `health_check_path` - (Optional) Relative path for health checks.
- `health_check_eviction_time_in_min` - (Optional) Time (in minutes) before unhealthy instances are evicted.
- `http2_enabled` - (Optional) Enables HTTP/2 support. Defaults to `false`.
- `ip_restriction_default_action` - (Optional) Default action for IP restrictions. Defaults to `"Allow"`.
- `load_balancing_mode` - (Optional) Load balancing mode used for requests.
- `managed_pipeline_mode` - (Optional) App pipeline mode. Defaults to `"Integrated"`.
- `minimum_tls_version` - (Optional) Minimum TLS version supported. Defaults to `"1.2"`.
- `pre_warmed_instance_count` - (Optional) Number of pre-warmed workers for faster startup.
- `remote_debugging_enabled` - (Optional) Enables remote debugging. Defaults to `false`.
- `remote_debugging_version` - (Optional) Remote debugger version. Defaults to `"VS2022"`.
- `runtime_scale_monitoring_enabled` - (Optional) Enables runtime scale monitoring.
- `scm_ip_restriction_default_action` - (Optional) Default SCM IP restriction action. Defaults to `"Allow"`.
- `scm_minimum_tls_version` - (Optional) SCM endpoint's minimum TLS version. Defaults to `"1.2"`.
- `scm_use_main_ip_restriction` - (Optional) Whether SCM uses main IP restrictions.
- `use_32_bit_worker` - (Optional) Run the app in a 32-bit worker process. Defaults to `true`.
- `vnet_route_all_enabled` - (Optional) All traffic routed through the VNet. Defaults to `false`.
- `websockets_enabled` - (Optional) Enable WebSocket support. Defaults to `false`.
- `worker_count` - (Optional) Number of workers to be allocated.

- `cors` - (Optional) Cross-Origin Resource Sharing configuration block.
  - `allowed_origins` - (Optional) List of origins allowed to make cross-origin calls.
  - `support_credentials` - (Optional) Whether to allow credentials in CORS requests. Defaults to `false`.

- `ip_restriction` - (Optional) List of IP restriction rules for the app.
  - `name` - (Optional) Name of the rule.
  - `action` - (Optional) Allow or Deny. Defaults to `"Allow"`.
  - `ip_address` - (Optional) IP address or CIDR to allow/deny.
  - `service_tag` - (Optional) Azure service tag (e.g. AzureFrontDoor.Backend).
  - `virtual_network_subnet_id` - (Optional) Subnet resource ID to allow/deny.
  - `priority` - (Optional) Rule priority. Defaults to `65000`.
  - `description` - (Optional) Description of the rule.
  - `headers` - (Optional) Header-based restrictions.
    - `x_azure_fdid` - (Optional) Azure Front Door ID list.
    - `x_fd_health_probe` - (Optional) Health probe header match.
    - `x_forwarded_for` - (Optional) X-Forwarded-For header values.
    - `x_forwarded_host` - (Optional) X-Forwarded-Host header values.

- `scm_ip_restriction` - (Optional) Same as `ip_restriction` but for the SCM endpoint.

- `app_service_logs` - (Optional) File system logging configuration block.
  - `disk_quota_mb` - (Optional) Max disk quota in MB. Defaults to `35`.
  - `retention_period_days` - (Optional) Retention in days. Defaults to `7`.

- `application_stack` - (Optional) Application stack configuration block.
  - `dotnet_version` - (Optional) .NET version.
  - `use_dotnet_isolated_runtime` - (Optional) Use isolated .NET worker runtime.
  - `java_version` - (Optional) Java version.
  - `node_version` - (Optional) Node.js version.
  - `powershell_core_version` - (Optional) PowerShell Core version.
  - `use_custom_runtime` - (Optional) Use custom runtime (e.g., Docker).
DESCRIPTION

}


variable "sticky_settings" {
  type = object({
    app_setting_names       = optional(list(string))
    connection_string_names = optional(list(string))
  })
  default     = null
  description = <<DESCRIPTION
(Optional) Lists of app/connection-string names that should *not* swap between slots.
- `app_setting_names`       - (Optional) Sticky app settings.
- `connection_string_names` - (Optional) Sticky connection strings.
DESCRIPTION
}

variable "storage_account" {
  type = list(object({
    name         = string
    type         = string
    account_name = string
    access_key   = string
    share_name   = string
    mount_path   = optional(string)
  }))
  default     = []
  description = <<DESCRIPTION
(Optional) File-share mounts made available to the runtime.
- `name`         - Name of the mount.
- `type`         - Type of storage (e.g., AzureFiles).
- `account_name` - Storage account name.
- `access_key`   - Access key for the storage.
- `share_name`   - Name of the share.
- `mount_path`   - (Optional) Path where it will be mounted.
DESCRIPTION
}