# =============================================================================
# MikroTik WireGuard VPN Module - Basic Tests
# =============================================================================

# Test 1: Basic WireGuard server creation
run "basic_wireguard_server" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_port     = 51820
    wireguard_subnet   = "10.10.50.0/24"
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.name == "wireguard1"
    error_message = "WireGuard interface name should be wireguard1"
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.listen_port == 51820
    error_message = "WireGuard should listen on port 51820"
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.mtu == 1420
    error_message = "MTU should be 1420"
  }
}

# Test 2: Gateway IP assignment
run "gateway_ip" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "192.168.50.0/24"
  }
  
  assert {
    condition     = can(regex("^192\\.168\\.50\\.1", routeros_ip_address.wg_ip.address))
    error_message = "Gateway IP should be 192.168.50.1"
  }
}

# Test 3: Single peer configuration
run "single_peer" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      "admin1" = {
        public_key  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        allowed_ips = "10.10.50.10/32"
        comment     = "Administrator 1"
      }
    }
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 1
    error_message = "Should create 1 peer"
  }
  
  assert {
    condition     = routeros_interface_wireguard_peer.peers["admin1"].public_key == "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    error_message = "Peer public key should match"
  }
  
  assert {
    condition     = routeros_interface_wireguard_peer.peers["admin1"].allowed_address == "10.10.50.10/32"
    error_message = "Peer should have correct IP"
  }
}

# Test 4: Multiple peers
run "multiple_peers" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      "admin1" = {
        public_key  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        allowed_ips = "10.10.50.10/32"
        comment     = "Admin 1"
      }
      "admin2" = {
        public_key  = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
        allowed_ips = "10.10.50.11/32"
        comment     = "Admin 2"
      }
      "teacher1" = {
        public_key  = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
        allowed_ips = "10.10.50.20/32"
        comment     = "Teacher 1"
      }
    }
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 3
    error_message = "Should create 3 peers"
  }
}

# Test 5: NAT masquerade rule
run "nat_masquerade" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
  }
  
  assert {
    condition     = routeros_ip_firewall_nat.wg_masquerade.chain == "srcnat"
    error_message = "NAT should be in srcnat chain"
  }
  
  assert {
    condition     = routeros_ip_firewall_nat.wg_masquerade.action == "masquerade"
    error_message = "NAT action should be masquerade"
  }
  
  assert {
    condition     = routeros_ip_firewall_nat.wg_masquerade.src_address == "10.10.50.0/24"
    error_message = "NAT should apply to VPN subnet"
  }
}

# Test 6: No peers (server only)
run "no_peers" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers              = {}
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 0
    error_message = "Should create 0 peers"
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.name == "wireguard1"
    error_message = "Server should still be created"
  }
}

# Test 7: Custom port
run "custom_port" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_port     = 13231
    wireguard_subnet   = "10.10.50.0/24"
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.listen_port == 13231
    error_message = "Should use custom port 13231"
  }
}

# Test 8: Peer with persistent keepalive
run "peer_keepalive" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      "mobile_user" = {
        public_key           = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE="
        allowed_ips          = "10.10.50.30/32"
        comment              = "Mobile User"
        persistent_keepalive = 30
      }
    }
  }
  
  assert {
    condition     = routeros_interface_wireguard_peer.peers["mobile_user"].persistent_keepalive == 30
    error_message = "Peer should have keepalive of 30 seconds"
  }
}

# Test 9: Outputs verification
run "outputs_check" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      "admin1" = {
        public_key  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        allowed_ips = "10.10.50.10/32"
      }
    }
  }
  
  assert {
    condition     = output.peer_count == 1
    error_message = "Peer count should be 1"
  }
  
  assert {
    condition     = contains(output.peer_list, "admin1")
    error_message = "Peer list should contain admin1"
  }
  
  assert {
    condition     = can(regex("wireguard1", output.wireguard_interface.name))
    error_message = "Interface output should contain wireguard1"
  }
}
