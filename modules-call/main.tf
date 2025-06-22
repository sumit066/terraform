# This is a test module for the Windows Function App module.

resource "azurerm_service_plan" "plan" {
  name                = "plan-func"
  location            = local.region
  resource_group_name = "test-rg"
  os_type             = "Windows"
  sku_name            = "Y1"
}
module "win_func_app" {
  source = "../terraform-azurerm-res-windows-function-app"

  # REQUIRED 
  name                          = "test-func"
  location                      = local.region
  resource_group_name           = "testrg"
  service_plan_id               = azurerm_service_plan.plan.id
  storage_account_name          = "testsa"
  storage_uses_managed_identity = true # ★ using MI – just run `terraform apply`

  # app_settings = {
  #   FUNCTIONS_EXTENSION_VERSION    = "~4"
  #   FUNCTIONS_WORKER_RUNTIME       = "dotnet"
  #   APPINSIGHTS_INSTRUMENTATIONKEY = azurerm_application_insights.ai.instrumentation_key
  # }

  # SITE CONFIG 

  site_config = {
    always_on     = true
    http2_enabled = true

  }
}