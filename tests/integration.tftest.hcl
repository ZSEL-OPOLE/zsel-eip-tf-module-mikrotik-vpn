# =============================================================================
# MikroTik WireGuard VPN Module - Integration Tests
# =============================================================================

# Test 1: Full VPN setup with multiple peer types
run "full_vpn_setup" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_port     = 51820
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      # Administrators
      "admin-laptop-01" = {
        public_key  = "ADMIN1_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "10.10.50.10/32"
        comment     = "Łukasz Kołodziej (Laptop)"
        persistent_keepalive = 25
      }
      "admin-laptop-02" = {
        public_key  = "ADMIN2_PUBLIC_KEY_BBBBBBBBBBBBBBBBBBBBBBB="
        allowed_ips = "10.10.50.11/32"
        comment     = "Damian Florek (Laptop)"
        persistent_keepalive = 25
      }
      # Mobile devices
      "admin-mobile-01" = {
        public_key  = "MOBILE1_PUBLIC_KEY_CCCCCCCCCCCCCCCCCCCCCCC="
        allowed_ips = "10.10.50.20/32"
        comment     = "Admin iPhone"
        persistent_keepalive = 30
      }
      # Teachers
      "teacher-laptop-01" = {
        public_key  = "TEACHER1_PUBLIC_KEY_DDDDDDDDDDDDDDDDDDDDDD="
        allowed_ips = "10.10.50.30/32"
        comment     = "Teacher access (limited)"
        persistent_keepalive = 25
      }
    }
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 4
    error_message = "Should create 4 peers (2 admins, 1 mobile, 1 teacher)"
  }
  
  assert {
    condition     = routeros_interface_wireguard.wg_server.listen_port == 51820
    error_message = "Server should listen on port 51820"
  }
  
  assert {
    condition     = can(regex("^10\\.10\\.50\\.1", routeros_ip_address.wg_ip.address))
    error_message = "Gateway should be 10.10.50.1"
  }
}

# Test 2: Large peer count (stress test)
run "large_peer_count" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      for i in range(10, 60) : "user-${i}" => {
        public_key  = "USER${i}_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "10.10.50.${i}/32"
        comment     = "User ${i}"
      }
    }
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 50
    error_message = "Should handle 50 peers"
  }
  
  assert {
    condition     = output.peer_count == 50
    error_message = "Peer count output should be 50"
  }
}

# Test 3: BCU production scenario (K3s VPN - VLAN 50)
run "bcu_k8s_vpn" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_port     = 51820
    wireguard_subnet   = "10.10.50.0/24"  # VLAN 50 from BCU plan
    peers = {
      "mac-k3s-master-01" = {
        public_key  = "MASTER1_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "10.10.50.11/32"
        comment     = "K3s Master 01 (Mac Pro M2 Ultra)"
      }
      "mac-k3s-master-02" = {
        public_key  = "MASTER2_PUBLIC_KEY_BBBBBBBBBBBBBBBBBBBBBBB="
        allowed_ips = "10.10.50.12/32"
        comment     = "K3s Master 02 (Mac Pro M2 Ultra)"
      }
      "mac-k3s-master-03" = {
        public_key  = "MASTER3_PUBLIC_KEY_CCCCCCCCCCCCCCCCCCCCCCC="
        allowed_ips = "10.10.50.13/32"
        comment     = "K3s Master 03 (Mac Pro M2 Ultra)"
      }
    }
  }
  
  assert {
    condition     = length(routeros_interface_wireguard_peer.peers) == 3
    error_message = "Should create 3 peers for K8s masters"
  }
  
  # Verify NAT for K8s subnet access
  assert {
    condition     = routeros_ip_firewall_nat.wg_masquerade.src_address == "10.10.50.0/24"
    error_message = "NAT should allow VPN clients to access K8s networks"
  }
}

# Test 4: Different subnet sizes
run "different_subnets" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "172.20.50.0/28"  # Small subnet (/28 = 14 hosts)
    peers = {
      "user1" = {
        public_key  = "USER1_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "172.20.50.10/32"
      }
    }
  }
  
  assert {
    condition     = can(regex("^172\\.20\\.50\\.1", routeros_ip_address.wg_ip.address))
    error_message = "Gateway should be first usable IP in /28"
  }
  
  assert {
    condition     = routeros_ip_firewall_nat.wg_masquerade.src_address == "172.20.50.0/28"
    error_message = "NAT should match /28 subnet"
  }
}

# Test 5: Peer comment defaults
run "peer_comment_defaults" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      "no-comment-user" = {
        public_key  = "NOCOMMENT_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "10.10.50.50/32"
        # comment not provided
      }
    }
  }
  
  # Should use default comment format
  assert {
    condition     = can(regex("WireGuard peer: no-comment-user", routeros_interface_wireguard_peer.peers["no-comment-user"].comment))
    error_message = "Should use default comment when not provided"
  }
}

# Test 6: Custom keepalive values
run "custom_keepalive" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    peers = {
      "default-keepalive" = {
        public_key  = "USER1_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "10.10.50.10/32"
        # persistent_keepalive not provided - uses default 25
      }
      "custom-keepalive" = {
        public_key           = "USER2_PUBLIC_KEY_BBBBBBBBBBBBBBBBBBBBBB="
        allowed_ips          = "10.10.50.11/32"
        persistent_keepalive = 60
      }
    }
  }
  
  assert {
    condition     = routeros_interface_wireguard_peer.peers["default-keepalive"].persistent_keepalive == 25
    error_message = "Default keepalive should be 25 seconds"
  }
  
  assert {
    condition     = routeros_interface_wireguard_peer.peers["custom-keepalive"].persistent_keepalive == 60
    error_message = "Custom keepalive should be 60 seconds"
  }
}

# Test 7: Integration with existing network
run "network_integration" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "192.168.50.0/24"
    peers = {
      "remote-admin" = {
        public_key  = "ADMIN_PUBLIC_KEY_AAAAAAAAAAAAAAAAAAAAAAAA="
        allowed_ips = "192.168.50.10/32"
        comment     = "Remote administrator"
      }
    }
  }
  
  # Verify interface is created
  assert {
    condition     = routeros_interface_wireguard.wg_server.name == "wireguard1"
    error_message = "Interface should be wireguard1"
  }
  
  # Verify gateway IP
  assert {
    condition     = can(regex("^192\\.168\\.50\\.1", routeros_ip_address.wg_ip.address))
    error_message = "Gateway should be 192.168.50.1"
  }
  
  # Verify NAT excludes VPN interface
  assert {
    condition     = routeros_ip_firewall_nat.wg_masquerade.out_interface == "!wireguard1"
    error_message = "NAT should exclude WireGuard interface itself"
  }
}

# Test 8: Client config template output
run "client_config_template" {
  command = plan
  
  variables {
    server_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    wireguard_subnet   = "10.10.50.0/24"
    wireguard_port     = 51820
  }
  
  assert {
    condition     = can(regex("\\[Interface\\]", output.client_config_template))
    error_message = "Client config should contain [Interface] section"
  }
  
  assert {
    condition     = can(regex("\\[Peer\\]", output.client_config_template))
    error_message = "Client config should contain [Peer] section"
  }
  
  assert {
    condition     = can(regex("51820", output.client_config_template))
    error_message = "Client config should include server port"
  }
}
