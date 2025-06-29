terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>2.115"
    }
    azuredevops = {
      source  = "microsoft/azuredevops"
      version = "~> 1.6"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "927eb769-0ff0-4640-9e6e-19f3d08ffaf9"
}

# provider "azurerm" {
#   alias           = "connectivity"
#   subscription_id = local.global_settings.subscription_ids["connectivity"]
#   features {}
# }

# provider "azurerm" {
#   alias           = "spoke"
#   subscription_id = "927eb769-0ff0-4640-9e6e-19f3d08ffaf9"
#   features {}
# }

# provider "azuredevops" {
#   org_service_url       = "https://dev.azure.com/ConclusionEnabled"
#   personal_access_token = "4K99CW4jZpNleDynpTeHobvvApHdKW6bEpJQ2ureedUmBv1AHw0jJQQJ99BCACAAAAAV3KD2AAASAZDO1Y5t"
# }

