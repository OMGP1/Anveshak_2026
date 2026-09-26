# Isolated management LAN deployment contract

This source configuration supports the planned single-node, 2–10 analyst installation. It does not prove that a hardware diode, switch policy, firewall, offline CA, or trusted time source has been installed correctly.

Required topology:

- VLAN 40 is `10.10.40.0/24`; the application management NIC is `10.10.40.10` and local infrastructure is `10.10.40.53`.
- Analyst reservations are `.101` through `.110`. DHCP advertises no default router. Switch ports use workstation-to-workstation isolation and DHCP snooping.
- `anveshak.soc.internal` resolves locally to `.10`; the gateway certificate SAN is that name. There is no upstream DNS forwarding, internet router, NAT, proxy, Wi-Fi, or cellular path.
- The capture NIC has no IPv4/IPv6 address, autoconfiguration, forwarding, or bridge membership. It is connected only to the receive side of the physical optical boundary.
- The Python API, databases, copilot runtime, and model files remain on private service networks. Analysts reach only gateway TCP 8443.

Copy `management-lan.env.example` to the Compose project `.env` only after the management NIC owns
`10.10.40.10`; the base Compose file reads `SIH_GATEWAY_BIND` and otherwise stays safely on loopback.
Before applying `compose.management-lan.yml`, record and review:

1. `ip -br address`, `ip -4 route`, `ip -6 route`, `bridge link`, `ss -lntup`, and `nft list ruleset`.
2. Switch VLAN, private-port, DHCP-snooping, and transparent-firewall exports.
3. The offline root/leaf certificate fingerprints, gateway hostname, separately pinned ledger/model trust keys, local time source, drift, and last verification.
4. A negative egress test for IPv4 and IPv6, including DNS, HTTP(S), ICMP, and attempts from the capture interface.
5. Two-user conflicting claim tests, then 5- and 10-session alert/case/copilot load tests. Record latency, queue drops, detector loss, and exact hardware.

Use `dnsmasq.conf` only on the approved `.53` infrastructure host after adapting the interface name and assigning fixed DHCP reservations. Use `nftables.nft` as a reviewed starting point, not as a blind installer. BMC, storage, console, and maintenance networks must not bypass the boundary.

The gateway currently provides local per-user sessions and viewer/operator/admin enforcement. Its trusted headers include both role and actor ID and are stripped/recreated at the proxy. A future Keycloak/OIDC migration must retain these backend contracts and pass issuer, audience, signature, PKCE, expiry, revocation, origin, and active-WebSocket revocation tests before replacing local credentials.
