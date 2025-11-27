# =============================================================================
# MikroTik WireGuard VPN Module
# =============================================================================
# Purpose: Configure WireGuard VPN server for remote access (1030 users)
# Port: 51820/UDP
# Subnet: 192.168.50.0/24 (VLAN 50)
# =============================================================================

terraform {
  required_providers {
    routeros = {
      source  = "terraform-routeros/routeros"
      version = "~> 1.0"
    }
  }
}

# =============================================================================
# Input Variables
# =============================================================================

variable "wireguard_port" {
  description = "WireGuard listen port (UDP)"
  type        = number
  default     = 51820

  validation {
    condition     = var.wireguard_port >= 1 && var.wireguard_port <= 65535
    error_message = "Port must be between 1 and 65535."
  }
}

variable "wireguard_subnet" {
  description = "WireGuard VPN subnet (CIDR notation)"
  type        = string
  default     = "192.168.50.0/24"

  validation {
    condition     = can(cidrhost(var.wireguard_subnet, 0))
    error_message = "Subnet must be valid CIDR notation."
  }
}

variable "server_private_key" {
  description = "WireGuard server private key (base64 encoded)"
  type        = string
  sensitive   = true
  # Generate with: wg genkey
  # MUST be provided via terraform.tfvars or env variable
}

variable "peers" {
  description = "Map of WireGuard peers (users)"
  type = map(object({
    public_key    = string           # User's public key (wg pubkey < private_key)
    allowed_ips   = string           # IP assigned to user (e.g., "192.168.50.10/32")
    comment       = optional(string) # User name/description
    persistent_keepalive = optional(number, 25)  # Keep NAT alive (seconds)
  }))
  default = {}
  
  # Example:
  # peers = {
  #   "user1" = {
  #     public_key  = "PUBLIC_KEY_BASE64"
  #     allowed_ips = "192.168.50.10/32"
  #     comment     = "Jan Kowalski (IT Admin)"
  #   }
  # }
}

# =============================================================================
# WireGuard Interface - Create VPN server
# =============================================================================

resource "routeros_interface_wireguard" "wg_server" {
  name        = "wireguard1"
  listen_port = var.wireguard_port
  private_key = var.server_private_key
  mtu         = 1420
  comment     = "WireGuard VPN Server - Terraform managed"
}

# =============================================================================
# IP Address - Assign IP to WireGuard interface
# =============================================================================

resource "routeros_ip_address" "wg_ip" {
  address   = cidrhost(var.wireguard_subnet, 1)  # e.g., 192.168.50.1/24
  interface = routeros_interface_wireguard.wg_server.name
  comment   = "WireGuard VPN Gateway IP"
}

# =============================================================================
# WireGuard Peers - Add users
# =============================================================================

resource "routeros_interface_wireguard_peer" "peers" {
  for_each = var.peers

  interface            = routeros_interface_wireguard.wg_server.name
  public_key           = each.value.public_key
  allowed_address      = [each.value.allowed_ips]  # Must be a list
  persistent_keepalive = each.value.persistent_keepalive
  comment              = coalesce(each.value.comment, "WireGuard peer: ${each.key}")
}

# =============================================================================
# NAT Rule - Allow VPN clients to access internal networks
# =============================================================================

resource "routeros_ip_firewall_nat" "wg_masquerade" {
  chain         = "srcnat"
  action        = "masquerade"
  src_address   = var.wireguard_subnet
  out_interface = "!wireguard1"  # All interfaces except WireGuard itself
  comment       = "SNAT for WireGuard VPN clients -> Internal networks"
}

# =============================================================================
# Routing - Add route for VPN subnet
# =============================================================================

# Note: MikroTik automatically creates connected route when IP is assigned
# No explicit route needed unless using policy-based routing

# =============================================================================
# Outputs
# =============================================================================

output "wireguard_interface" {
  description = "WireGuard interface details"
  value = {
    name        = routeros_interface_wireguard.wg_server.name
    listen_port = routeros_interface_wireguard.wg_server.listen_port
    mtu         = routeros_interface_wireguard.wg_server.mtu
  }
}

output "wireguard_gateway_ip" {
  description = "WireGuard gateway IP address"
  value       = routeros_ip_address.wg_ip.address
}

output "wireguard_public_key" {
  description = "Server's WireGuard public key (for client configs)"
  value       = routeros_interface_wireguard.wg_server.public_key
  sensitive   = false
}

output "peer_count" {
  description = "Number of configured WireGuard peers"
  value       = length(var.peers)
}

output "peer_list" {
  description = "List of configured peer names"
  value       = keys(var.peers)
}

# =============================================================================
# Client Configuration Template
# =============================================================================

output "client_config_template" {
  description = "WireGuard client configuration template"
  value = <<-EOT
  # WireGuard Client Configuration Template
  # Save as: wg-client.conf
  
  [Interface]
  PrivateKey = CLIENT_PRIVATE_KEY_HERE
  Address = 192.168.50.X/32  # Assigned IP from peers map
  DNS = 192.168.10.1         # Or your DNS server
  
  [Peer]
  PublicKey = ${routeros_interface_wireguard.wg_server.public_key}
  Endpoint = YOUR_PUBLIC_IP:${var.wireguard_port}
  AllowedIPs = 192.168.0.0/16  # Access to all internal VLANs
  PersistentKeepalive = 25
  
  # To generate client keys:
  # Private key: wg genkey
  # Public key:  wg pubkey < private_key
  EOT
}
