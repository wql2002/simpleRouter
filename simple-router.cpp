/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  fprintf(stderr, "\n\n");
  fprintf(stderr, "-------------------------new packet---------------------------\n");
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  //-------------------------------my code--------------------------------
  // print_hdrs(packet);
  const uint8_t* buf = packet.data();
  uint32_t length = packet.size();
  /* Ethernet */
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(ip_hdr);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    // get IP header in Ethernet frame
    const ip_hdr *iphdr = (const ip_hdr *)(buf + sizeof(ethernet_hdr));
    const uint16_t ip_len = ntohs(iphdr->ip_len);

    // checksum (this function compute the checksum still in NBO(Network Bit Order))
    uint16_t new_cksum = cksum(buf, ip_len);
    if(iphdr->ip_sum != new_cksum) {
        fprintf(stderr, "Checksum error, ignore this packet\n");
        return;
    }

    uint8_t ip_proto = iphdr->ip_p;
    // uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(icmp_hdr);
      if (length < minlength) {
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
        return;
      }
      else {

      }
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(arp_hdr);
    if (length < minlength) {
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
      return;
    }
    else {
      // get ARP header in Ethernet frame
      const arp_hdr *arphdr = reinterpret_cast<const arp_hdr*>(buf + sizeof(ethernet_hdr));
      // do i have the hardware type "Ethernet"?
      if(ntohs(arphdr->arp_hrd) != arp_hrd_ethernet) {
        fprintf(stderr, "Failed to match arp_hrd, Incorrect hardware type\n");
        return;
      }
      else {
        fprintf(stderr, "Succed to match arp_hrd\n");
        // do i speak the protocol "IPv4"?
        if(ntohs(arphdr->arp_pro) != ethertype_ip) {
          fprintf(stderr, "Failed to match arp_pro, Incorrect protocol type\n");
          return;
        }
        else {
          fprintf(stderr, "Succeed to match arp_pro\n");
          // am I the target protocol address (IP address)?
          // get this interface's ip by iface.ip
          // get MAC by iface.addr
          if(iface->ip != arphdr->arp_tip) {
            fprintf(stderr, "Failed to match arp_tip, Incorrect target protocol address\n");
            // print_addr_ip_int(ntohl(arphdr->arp_tip));
            // std::cerr << ipToString(iface->ip) << std::endl;
            // std::cerr << ipToString(arphdr->arp_tip) << std::endl;
            return;
          }
          else {
            fprintf(stderr, "Succeed to match arp_tip\n");
            // is the opcode "REQUEST"?
            // std::cerr << ntohs(arphdr->arp_op) << std::endl;
            // std::cerr << arp_op_request << std::endl;
            if(ntohs(arphdr->arp_op) == arp_op_request) { /* request */
              fprintf(stderr, "Succeed to receive a ARP request packet\n");
              // swap hardware and protocol field

              // Ethernet header
              const uint8_t* if_MAC = iface->addr.data();
              // memcpy(ehdr->ether_dhost, ehdr->ether_shost, sizeof(ehdr->ether_shost));
              // memcpy(ehdr->ether_shost, if_MAC, sizeof(if_MAC));
              memcpy(ehdr->ether_dhost, ehdr->ether_shost, 6);
              memcpy(ehdr->ether_shost, if_MAC, 6);

              // ARP header
              // arphdr->tha = arphdr->sha; // hardware addr
              memcpy(arphdr->tha, arphdr->sha, 6);
              arphdr->tip = arphdr->sip; // ip addr
              // arphdr->sha = iface->addr;
              memcpy(arphdr->sha, if_MAC, 6);
              arphdr->sip = iface->ip;
              // opcode
              //arphdr->arp_op = arp_op_reply;
              // test
              print_hdr_eth(buf);
              print_hdr_arp(buf + sizeof(ethernet_hdr));
            }
            else { /* reply */
              fprintf(stderr, "Succeed to receive a ARP reply packet\n");
            }
          }
        }
      }
    }
  }
  else { /* ignore other Ethernet frames */
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
  //-------------------------------my code--------------------------------

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
