---
layout: post
title: Malicious Time-to-Live (TTL) manipulation
date: 2024-03-15 19:50:00-0400
description: A high-level explanation on malicious TTL manipulation and packet fragmentation.
tags: IDS IPS TTL packet-fragmentation ICMP network-security
categories: Explainers
thumbnail: /assets/img/2024/202403-TTL.webp
giscus_comments: false
related_posts: true
toc:
  sidebar: left
featured: false
---

Threat actors can manipulate their IP packets' Time-to-Live (TTL) value to evade detection while performing network reconnaissance and even help bypass firewalls, Intrusion Detection Systems (IDS), and Intrusion Prevention Systems (IPS).

But first, what is TTL...

## What is TTL
Time-to-live (TTL) is a mechanism used in computing to limit the lifespan or validity of data in a network. TTL is a value included in IP packets that tells a network router how many hops (transfers from one network segment to another) the packet is allowed before it should be discarded. The TTL value prevents data packets from circulating indefinitely and causing network congestion. 

TTL values are set in the header of IP packets. The TTL value is an 8-bit field, ranging from 0 to 255. The value set in this field determines the maximum number of routers (hops) the packet can pass through before it is discarded or dropped. 

The initial TTL value of a packet can vary depending on the operating system or the application generating the packet. Some common initial values used by different systems include:
Linux-based systems - 64.
Windows-based systems -128.
Network equipment like Cisco routers -255.

The choice of the initial TTL value is a balance between ensuring that packets have enough hops to reach their destination under normal conditions and preventing packets from circulating unnecessarily - an important feature to mitigate network congestion.

## What happens when the TTL reaches 0
When the TTL value of an IP packet decrements to 0, it indicates that the packet has reached the maximum allowed number of hops (routers) without reaching its intended destination. The router that decrements the TTL value to 0 will discard the packet and typically sends an ICMP (Internet Control Message Protocol) Time Exceeded message back to the source IP address. This ICMP message notifies the sender that the packet was not delivered due to the TTL expiring.

## TTL Manipulation for reconnaissance and probing
Intentionally manipulating the TTL with lower-than-normal values can be used in network reconnaissance. By controlling the TTL value, a threat actor can elicit the ICMP Time Exceeded response from various appliances on a network. These responses can help infer the overall layout, map network paths, or identify the presence and location of specific appliances.

## Bypassing Security Measures
Another application of TTL manipulation involves deceiving IDS and IPS appliances to smuggle malicious packets past these security controls. 

This technique operates on the principle of sending two sets of packets with carefully selected TTL values and identical sequence numbers, exploiting the way some security devices handle packet inspection and filtering.

### Initial Probing Packets
The threat actor sends a series of packets towards the target system with TTL values calibrated such that they expire right before reaching the target, yet after passing the IDS/IPS. These packets, designed to appear benign, prompt the IDS/IPS to log their sequences but ultimately discard them as they do not reach the destination due to TTL expiry.

### Follow-Up Malicious Packets
Subsequently, the attacker sends another set of packets with identical sequence numbers as the probing packets, but this time, containing a malicious payload. These packets are sent with TTL values that ensure they reach the target. The critical manipulation here lies in setting the TTL of the probing packets to expire just beyond the IDS/IPS, thus avoiding further inspection of the subsequent malicious packets.

### The IDS/IPS Deception
Many IDS/IPS configurations are optimised to reduce performance overhead, which includes minimising duplicate packet inspection. They might treat these follow-up packets as duplicates of the initial, already-checked sequence, thus not subjecting them to thorough scrutiny. Consequently, the packets carrying the malicious content bypass the IDS/IPS checks, reaching the target system unnoticed.

### Implications for Security
This advanced method illustrates the capacity for TTL manipulation in mapping network defences and its potential in crafting evasion strategies that exploit specific weaknesses in the security infrastructure's logic and configuration. 

## Incorporating Fragmentation with TTL Manipulation
Another method combines packet fragmentation with TTL manipulation to evade security controls. This technique leverages the fact that some security devices may not thoroughly inspect or reassemble fragmented packets. 

By fragmenting malicious payloads and carefully setting the TTL values, attackers can craft packets that are less likely to be detected by traditional security mechanisms.

Fragmenting packets involves dividing the malicious payload into smaller fragments, making it more challenging for security devices to identify and block the harmful content, as the payload isn't contained within a single, easily inspectable packet.

Alongside fragmentation, the attacker manipulates the TTL values to ensure that the fragmented packets bypass the security devices with minimal scrutiny. The manipulated TTL values can help ensure that the fragments take a path through the network that avoids comprehensive inspection or takes advantage of devices that do not reassemble packets for inspection.

By carefully orchestrating the fragmentation and TTL settings, the attacker can potentially deliver the malicious payload past IDS, IPS, and firewalls. Once the fragments reach their target, they can be reassembled into the original malicious payload, executing the intended attack without being detected by the network's security infrastructure.

## Mitigation and real-world application
The effectiveness of these techniques in real-world scenarios can significantly vary. Modern Intrusion Detection and Prevention Systems are designed to mitigate such evasion tactics. 

These systems often incorporate advanced algorithms and analysis of behaviour patterns to detect and counteract unusual TTL values and fragmented packet strategies.

To enhance network security against such TTL manipulation techniques, administrators can consider the following mitigation strategies:
Enhanced Packet Inspection: Configure IDS/IPS to perform in-depth packet inspections, including analysing fragmented packets and verifying packet integrity.

- **Anomaly Detection:** Implement anomaly-based detection systems that identify unusual traffic patterns, including atypical TTL values.
Regular Updates and Patching: Keep security devices updated with the latest software patches and threat intelligence to defend against new and evolving tactics.

- **Comprehensive Security Practices:** Employ a multi-layered security approach that includes encryption, firewalls, and end-to-end monitoring to reduce reliance on any single point of failure.
