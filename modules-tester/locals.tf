locals {
  region = "North Europe"
  # environment            = "development"

  tags = {
    billing_id = "12345"
  }

  global_settings = merge({ customer_name = "Contoso", customer_short_name = "cnts" }, {
    customer_name       = "Contoso"
    customer_short_name = "cnts"
    region              = "North Europe"
    workload            = "Connectivity"
    # environment            = "development"

    tags = {
      billing_id = "12345"
    }
    }, {
    subscription_ids = {
      connectivity = ""
      management   = ""
    }
  })

}