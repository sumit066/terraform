output "id" {
  value = azurerm_windows_function_app.wfunc.id
  description = "The ID of the Windows Function App."
}

output "custom_domain_verification_id" {
  value = azurerm_windows_function_app.wfunc.custom_domain_verification_id
  description = "The identifier used by App Service to perform domain ownership verification via DNS TXT record."
}

output "default_hostname" {
  value = azurerm_windows_function_app.wfunc.default_hostname
  description = "The default hostname of the Windows Function App."
}

output "hosting_environment_id" {
  value = azurerm_windows_function_app.wfunc.hosting_environment_id
  description = "The ID of the App Service Environment used by Function App."
}

output "identity" {
  value = azurerm_windows_function_app.wfunc.identity
  description = <<DESCRIPTION
An `identity` block as defined below.
- `principal_id`  - The Principal ID associated with this Managed Service Identity.
- `tenant_id`     - The Tenant ID associated with this Managed Service Identity.
DESCRIPTION
}

output "kind" {
  value = azurerm_windows_function_app.wfunc.kind
  description = "The Kind value for this Windows Function App."
}

output "outbound_ip_address_list" {
  value = azurerm_windows_function_app.wfunc.outbound_ip_address_list
  description = "A list of outbound IP addresses. For example `[52.23.25.3, 52.143.43.12]`."
}

output "outbound_ip_addresses" {
  value = azurerm_windows_function_app.wfunc.outbound_ip_addresses
  description = "A comma separated list of outbound IP addresses as a string. For example `52.23.25.3,52.143.43.12`."
}

output "possible_outbound_ip_address_list" {
  value = azurerm_windows_function_app.wfunc.possible_outbound_ip_address_list
  description = "A list of possible outbound IP addresses, not all of which are necessarily in use. This is a superset of `outbound_ip_address_list`. For example `[52.23.25.3, 52.143.43.12]`."
}

output "possible_outbound_ip_addresses" {
  value = azurerm_windows_function_app.wfunc.possible_outbound_ip_addresses
  description = "A comma separated list of possible outbound IP addresses as a string. For example `52.23.25.3,52.143.43.12,52.143.43.17`. This is a superset of `outbound_ip_addresses`."
}

output "site_credential" {
  value = azurerm_windows_function_app.wfunc.site_credential
  description = <<DESCRIPTION
A `site_credential` block as defined below.
- `name`      - The Site Credentials Username used for publishing.
- `password`  - The Site Credentials Password used for publishing.
DESCRIPTION
}