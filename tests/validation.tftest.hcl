# =============================================================================
# MikroTik WireGuard VPN Module - Validation Tests
# =============================================================================

# Mock provider configuration for testing without real RouterOS device
mock_provider "routeros" {}

# Test 1: Invalid port (too high)
run "invalid_port_high" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_port     = 99999
    wireguard_subnet   = "10.10.50.0/24"
  }
  
  expect_failures = [
    var.wireguard_port
  ]
}

# Test 2: Invalid port (zero)
run "invalid_port_zero" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_port     = 0
    wireguard_subnet   = "10.10.50.0/24"
  }
  
  expect_failures = [
    var.wireguard_port
  ]
}

# Test 3: Invalid subnet CIDR
run "invalid_subnet" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/33"
  }
  
  expect_failures = [
    var.wireguard_subnet
  ]
}

# Test 4: Malformed subnet
run "malformed_subnet" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.999.0/24"
  }
  
  expect_failures = [
    var.wireguard_subnet
  ]
}

# Test 5: Valid configuration
run "valid_config" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    wireguard_port     = 51820
    peers = {
      "user1" = {
        public_key  = "USER1_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "10.10.50.10/32"
      }
    }
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.listen_port == "51820"
    error_message = "Port should be 51820"
  }
}

# Test 6: Empty peer list
run "no_peers" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers              = {}
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 0
    error_message = "Should have no peers"
  }
}
