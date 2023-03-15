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
SimpleRouter::sendICMP(uint8_t type, uint8_t code, const Buffer& packet, const std::string& inIface)
{
  // ORIGIN PACKET
  const uint8_t* buf = packet.data();
  uint32_t length = packet.size();
  const Interface* iface = findIfaceByName(inIface);
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  ip_hdr *iphdr = (ip_hdr *)(buf + sizeof(ethernet_hdr));

  uint32_t icmp_len;
  // NEW PACKET
  if((type == icmp_time_exceeded) || (type == icmp_unreachable)) {
    // icmp_len = sizeof(ethernet_hdr)+sizeof(ip_hdr)+sizeof(icmp_t11_hdr);
    icmp_len = 70;
    Buffer icmp_packet(icmp_len, 0);
    // construct new header
    uint8_t* new_buf = icmp_packet.data();
    ethernet_hdr *new_ehdr = (ethernet_hdr *)new_buf;
    ip_hdr *new_iphdr = (ip_hdr *)(new_buf + sizeof(ethernet_hdr));
    icmp_t11_hdr* icmp_packethdr= (icmp_t11_hdr* )(new_buf + sizeof(ethernet_hdr)+sizeof(ip_hdr));

    // Ethernet header
    memcpy(new_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
    new_ehdr->ether_type = ntohs(ethertype_ip);

    // IP header
    memcpy(new_buf + sizeof(ethernet_hdr), iphdr, sizeof(ip_hdr));
    // new_iphdr->ip_len = (uint16_t)(sizeof(ip_hdr)+sizeof(icmp_t11_hdr));
    // note that > 8 bit need to use ntohs()
    new_iphdr->ip_len = ntohs(56);
    new_iphdr->ip_ttl = 64;
    new_iphdr->ip_p = ip_protocol_icmp;
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_dst = new_iphdr->ip_src;
    new_iphdr->ip_src = iface->ip;
    // compute cksum
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(ip_hdr));

    // ICMP header
    icmp_packethdr->icmp_type = type;
    icmp_packethdr->icmp_code = code;
    icmp_packethdr->icmp_sum = 0;
    // payload
    iphdr->ip_ttl--;
    memcpy(new_buf + sizeof(ethernet_hdr)+sizeof(ip_hdr)+8, iphdr, ICMP_DATA_SIZE);
    icmp_packethdr->icmp_sum = cksum(icmp_packethdr, sizeof(icmp_t11_hdr));
    fprintf(stderr, "icmp (time exceed/host unreachable) packet sent back:\n");
    print_hdrs(icmp_packet);
    print_hdr_ip(new_buf + sizeof(ethernet_hdr)+sizeof(ip_hdr)+8);
    
    // send back
    sendPacket(icmp_packet, iface->name);
    return;
  }
  else if(type == icmp_echo_reply) {
    icmp_t8_hdr* icmp_echoin_hdr = (icmp_t8_hdr *)(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
    // icmp_len = sizeof(ethernet_hdr)+sizeof(ip_hdr)+sizeof(icmp_t0_hdr);
    // Buffer icmp_packet(icmp_len, 0);
    Buffer icmp_packet(buf, buf+length);
    // construct new header
    uint8_t* new_buf = icmp_packet.data();
    ethernet_hdr *new_ehdr = (ethernet_hdr *)new_buf;
    ip_hdr *new_iphdr = (ip_hdr *)(new_buf + sizeof(ethernet_hdr));
    icmp_t0_hdr* icmp_packethdr= (icmp_t0_hdr* )(new_buf + sizeof(ethernet_hdr)+sizeof(ip_hdr));

    // Ethernet header
    memcpy(new_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
    new_ehdr->ether_type = ntohs(ethertype_ip);

    // IP header
    // memcpy(new_buf + sizeof(ethernet_hdr), iphdr, sizeof(ip_hdr));
    // len = 7168, cant figure out!!!
    // new_iphdr->ip_len = sizeof(ip_hdr)+sizeof(icmp_t0_hdr);
    // fprintf(stderr, "you know where: %d\n", sizeof(icmp_t0_hdr));
    // new_iphdr->ip_len = iphdr->ip_len;
    new_iphdr->ip_ttl = 64;
    new_iphdr->ip_p = ip_protocol_icmp;
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_dst = new_iphdr->ip_src;
    new_iphdr->ip_src = iface->ip;
    // compute cksum
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(ip_hdr));

    // ICMP header
    icmp_packethdr->icmp_type = type;
    icmp_packethdr->icmp_code = code;
    icmp_packethdr->icmp_sum = 0;
    icmp_packethdr->icmp_id = icmp_echoin_hdr->icmp_id;
    icmp_packethdr->icmp_seq = icmp_echoin_hdr->icmp_seq;
    icmp_packethdr->icmp_sum = cksum(icmp_packethdr, sizeof(icmp_t0_hdr));
    fprintf(stderr, "icmp echo reply packet sent back:\n");
    print_hdrs(icmp_packet);
    print_hdr_icmp_echo(new_buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));

    // send back
    sendPacket(icmp_packet, iface->name);
    return;
  }
  else { /* other ICMP type dont send */
    return;
  }
  // uint32_t icmp_packet_len = sizeof(ethernet_hdr)+sizeof(ip_hdr)+sizeof(icmp_t11_hdr);

  
}

void
SimpleRouter::sendForwardIP(const Buffer& mac, const Buffer& packet, const std::string& outIface) {
  fprintf(stderr, "Begin to forward IP datagram!\n");
  // ORIGIN PACKET
  const uint8_t* buf = packet.data();
  uint32_t length = packet.size();
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  // ip_hdr *iphdr = (ip_hdr *)(buf + sizeof(ethernet_hdr));

  const Interface* iface = findIfaceByName(outIface);

  // update Ethernet src/dst MAC
  memcpy(ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  memcpy(ehdr->ether_dhost, mac.data(), ETHER_ADDR_LEN);
  Buffer out_packet(buf, buf+length);
  sendPacket(out_packet, outIface);
  
  return;
}
 
void
SimpleRouter::sendARP(unsigned short opcode, const Buffer& packet, const std::string& inIface) {
  if(opcode == arp_op_request) { /* request */
    Buffer req_packet(sizeof(ethernet_hdr)+sizeof(arp_hdr), 0);
    const uint8_t* buf = req_packet.data();
    uint32_t length = req_packet.size();
    // origin IP packet (use its ip_dst)
    const uint8_t* ori_buf = packet.data();
    ip_hdr* ori_iphdr = (ip_hdr* )(ori_buf + sizeof(ethernet_hdr));
    const Interface* iface = findIfaceByName(inIface);
    /* Ethernet */
    ethernet_hdr *ehdr = (ethernet_hdr *)buf;
    const uint8_t* if_MAC = iface->addr.data();
    /* ARP header */
    arp_hdr *arphdr = (arp_hdr*)(buf + sizeof(ethernet_hdr));
    // broadcast mac
    const uint8_t broad_cast[ETHER_ADDR_LEN] = {255, 255, 255, 255, 255, 255};
    
    // Ethernet header
    memcpy(ehdr->ether_dhost, broad_cast, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, if_MAC, ETHER_ADDR_LEN);
    ehdr->ether_type = ntohs(ethertype_arp);

    // ARP header
    arphdr->arp_hrd = ntohs(arp_hrd_ethernet);
    arphdr->arp_pro = ntohs(0x800);
    arphdr->arp_hln = 0x6;
    arphdr->arp_pln = 0x4;
    arphdr->arp_op = ntohs(arp_op_request);
    memcpy(arphdr->arp_sha, if_MAC, ETHER_ADDR_LEN);
    arphdr->arp_sip = iface->ip;
    memcpy(arphdr->arp_tha, broad_cast, ETHER_ADDR_LEN);
    arphdr->arp_tip = ori_iphdr->ip_dst;

    print_hdr_eth(buf);
    print_hdr_arp(buf + sizeof(ethernet_hdr));

    // sent ARP Request 
    Buffer out_packet(buf, buf+length);

    // send ARP reply frame out through outIf
    sendPacket(out_packet, iface->name);
  }
  else { /* reply*/
    const uint8_t* buf = packet.data();
    uint32_t length = packet.size();
    const Interface* iface = findIfaceByName(inIface);
    /* Ethernet */
    ethernet_hdr *ehdr = (ethernet_hdr *)buf;
    const uint8_t* if_MAC = iface->addr.data();
    /* ARP header */
    arp_hdr *arphdr = (arp_hdr*)(buf + sizeof(ethernet_hdr));


    // Ethernet header
    memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, if_MAC, ETHER_ADDR_LEN);

    // ARP header
    memcpy(arphdr->arp_tha, arphdr->arp_sha, ETHER_ADDR_LEN);
    arphdr->arp_tip = arphdr->arp_sip; // ip addr
    memcpy(arphdr->arp_sha, if_MAC, ETHER_ADDR_LEN);
    arphdr->arp_sip = iface->ip;

    // opcode: reply
    arphdr->arp_op = ntohs(arp_op_reply);
    
    // debug
    print_hdr_eth(buf);
    print_hdr_arp(buf + sizeof(ethernet_hdr));

    // sent ARP reply 
    Buffer out_packet(buf, buf+length);

    // send ARP reply frame out through outIf
    sendPacket(out_packet, iface->name);
  }
}

void
SimpleRouter::processARP(const Buffer& packet) {
  fprintf(stderr, "succeed to receive ARP reply!\n");
  const uint8_t* buf = packet.data();
  // uint32_t length = packet.size();
  /* Ethernet */
  // ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  /* ARP header */
  arp_hdr *arphdr = (arp_hdr*)(buf + sizeof(ethernet_hdr));

  /*
  The ARP reply processing code should move entries from the ARP request
  queue to the ARP cache:

  # When servicing an arp reply that gives us an IP->MAC mapping
  req = cache.insertArpEntry(ip, mac)

  if req != nullptr:
      send all packets on the req->packets linked list
      cache.removeRequest(req)
  */
  Buffer sender_mac(arphdr->arp_sha, arphdr->arp_sha+ETHER_ADDR_LEN);
  auto req = m_arp.insertArpEntry(sender_mac, arphdr->arp_sip);
  fprintf(stderr, "hello1!\n");

  if(req != nullptr) {
    for(auto& m_pac: req->packets) {
      // forward all packet in req->packets
      sendForwardIP(sender_mac, m_pac.packet, m_pac.iface);
      m_arp.removeRequest(req);
    }
  }
  fprintf(stderr, "hello2!\n");
}

bool
SimpleRouter::checkDestined(uint32_t dst_ip) {
  // check if the dst ip match one of the router's interface
  for(auto& iface: m_ifaces) {
    if(dst_ip == iface.ip) {
      return true;
    }
  }
  return false;
}

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
  print_hdrs(packet);
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

  // check Ethernet header
  const uint8_t* if_MAC = iface->addr.data();
  const uint8_t broad_cast[ETHER_ADDR_LEN] = {255, 255, 255, 255, 255, 255};
  // ignore frame that target neithor this iface nor broadcast
  if(!check_eth_dest(ehdr->ether_dhost, if_MAC)) {
    if(!check_eth_dest(ehdr->ether_dhost, broad_cast)) {
      fprintf(stderr, "Failed to match Ethernet header target addr\n");
      return;
    }
  }

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(ip_hdr);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    // get IP header in Ethernet frame
    ip_hdr *iphdr = (ip_hdr *)(buf + sizeof(ethernet_hdr));

    // checksum (this function compute the checksum still in NBO(Network Bit Order))
    uint16_t old_cksum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    uint16_t new_cksum = cksum(iphdr, sizeof(ip_hdr));

    if(old_cksum != new_cksum) {
        fprintf(stderr, "1: Checksum error, ignore this packet\n");
        return;
    }
    fprintf(stderr, "Checksum match!\n");

    // IP DESTINATION ADDRESS (dont need to use "ntohl")
    uint32_t old_ip_dst = iphdr->ip_dst;

    // old_ip_dst == iface->ip
    if(checkDestined(old_ip_dst)) { /* destined to the router */
      // IP PROTOCOL TYPE
      uint8_t ip_proto = iphdr->ip_p;

      if (ip_proto == ip_protocol_icmp) { /* ICMP */
        minlength += sizeof(icmp_hdr);
        if (length < minlength) {
          fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
          return;
        }
        fprintf(stderr, "Succeed to receive ICMP datagram!\n");
        
        // check icmp type
        icmp_hdr* icmphdr = (icmp_hdr *)(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        print_hdr_icmp_echo(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        if(icmphdr->icmp_type == icmp_echo) {
          // ICMP ECHO REPLY
          sendICMP(icmp_echo_reply, 0, packet, inIface);
        }
        else {
          fprintf(stderr, "unknown ICMP packet, discard!\n");
          return;
        }
      }
      else if((ip_proto == ip_protocol_tcp) || (ip_proto == ip_protocol_udp)) { /* TCP or UDP*/
        fprintf(stderr, "Succeed to receive tcp/udp datagram!\n");
        // ICMP post unreachable
        sendICMP(icmp_unreachable, 3, packet, inIface);
      }
      else {
        fprintf(stderr, "Discard unkown type ip datagram!\n");
        return;
      }
    }
    else { /* datagrams to be forwarded */
      fprintf(stderr, "this datagram need to forward\n");
      // check TTL
      if((iphdr->ip_ttl == 0) || (iphdr->ip_ttl == 1)) {
        // discard and send ICMP time exceed packet
        sendICMP(icmp_time_exceeded, 0, packet, inIface);
        return;
      }
      // FORWARDING

      // look up forward table (longest prefix match)
      RoutingTableEntry next_entry = m_routingTable.lookup(old_ip_dst);
      std::cerr << ipToString(old_ip_dst) << std::endl;
      // fprintf(stderr, "next hop interface: !\n");
      std::cerr << ipToString(next_entry.dest) << "\t\t"
        << ipToString(next_entry.gw) << "\t"
        << ipToString(next_entry.mask) << "\t"
        << next_entry.ifName << std::endl;


      // update Ethernet header and recompute IP header(TTL, checksum)
      // update Ethernet source MAC
      const Interface* out_iface = findIfaceByName(next_entry.ifName);

      // update IP ttl, cksum
      iphdr->ip_ttl--;
      iphdr->ip_sum = 0;
      iphdr->ip_sum = cksum(iphdr, sizeof(ip_hdr));

      // look up ARP Cache
      std::shared_ptr<ArpEntry>out_entry = m_arp.lookup(old_ip_dst);
      fprintf(stderr, "succeed to find a arp entry.\n");
      if(out_entry != nullptr) {
        // update Ethernet dst MAC
        fprintf(stderr, "Find ARP entry, succeed to forward IP datagram!\n");
        sendForwardIP(out_entry->mac, packet, out_iface->name);
        return;
      }
      else {
        fprintf(stderr, "Fail to find ARP entry, add to queue!\n");
        // no <mac, ip> entry, enqueue that request
        Buffer out_packet(buf, buf+length);
        m_arp.queueRequest(old_ip_dst, out_packet, next_entry.ifName);
        return;
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
      arp_hdr *arphdr = (arp_hdr*)(buf + sizeof(ethernet_hdr));
      // do i have the hardware type "Ethernet"?
      if(ntohs(arphdr->arp_hrd) != arp_hrd_ethernet) {
        fprintf(stderr, "Failed to match arp_hrd, Incorrect hardware type\n");
        return;
      }
      else {
        fprintf(stderr, "Succeed to match arp_hrd\n");
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
            return;
          }
          else {
            fprintf(stderr, "Succeed to match arp_tip\n");
            // is the opcode "REQUEST"?
            if(ntohs(arphdr->arp_op) == arp_op_request) { /* request */
              fprintf(stderr, "Succeed to receive a ARP request packet\n");

              // SEND ARP REPLY
              sendARP(arp_op_reply, packet, inIface);
              return;
            }
            else { /* reply */
              fprintf(stderr, "Succeed to receive a ARP reply packet\n");
              //update ARP Cache and send queued packets
              processARP(packet);
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
  std::cerr << "@@Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

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
