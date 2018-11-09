package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.LinkedList;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/* For queueing while waiting for ARP replies */
	// private Map<Integer, Boolean> replyReceived;
	// private List<LinkedList<Integer>> queuedRequests;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file " + routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file " + arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/*class ARPThread implements Runnable {
		private Ethernet etherPacket;
		private Iface inIface;
		private Router caller;
		private int bestMatch;

		public ARPThread(Ethernet etherPacket, Iface inIface, Router caller, int bestMatch) {
			this.etherPacket = etherPacket;
			this.inIface = inIface;
			this.bestMatch = bestMatch;
			this.caller = caller;
		}

		public void run() {
			int requestCount = 0;
			Boolean received = false;
			while (requestCount < 3 && !received) {
				caller.sendArp(etherPacket, inIface, false);
				++requestCount;
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				// Check whether the calling Router has received the reply
				synchronized (replyReceived) {
					if (!replyReceived.isEmpty() && replyReceived.containsKey(bestMatch))
						received = replyReceived.get(bestMatch);
				}
			}
		}
	}*/

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets */

		switch (etherPacket.getEtherType()) {
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void sendICMP(Iface inIface, IPv4 ipPacket, byte type, byte code) {
		System.out.println("Inside the sendICMP method");

		/* Source is the destination for the return message. */
		int dstAddr = ipPacket.getSourceAddress();

		/* Find matching route table entry */
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		if (bestMatch == null)
			System.out.println("bestMatch is null");

		int nextHop = bestMatch.getGatewayAddress();
		System.out.println("Next Hop: " + nextHop);
		if (nextHop == 0)
			nextHop = dstAddr;

		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null)
			System.out.println("arpEntry is null");

		/*
		 * The source MAC is the MAC of the interface that the packet came in on
		 */
		MACAddress sourceMAC = inIface.getMacAddress();

		Ethernet ether = new Ethernet();

		/* Set Ip header fields */
		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		/* Set ICMP header fields */
		ICMP icmp = new ICMP();
		icmp.setIcmpType((byte) type);
		icmp.setIcmpCode((byte) code);

		/*
		 * Set the data to be the IP header and 8bytes following from the original
		 * packet.
		 */
		System.out.println("Header Length = " + ipPacket.getHeaderLength());
		byte[] dataArray = new byte[ipPacket.getHeaderLength() * 4 + 12];
		byte[] ipArray = ipPacket.serialize();
		ByteBuffer bb = ByteBuffer.wrap(dataArray);
		bb.putInt(0);
		for (int i = 0; i < dataArray.length - 4; ++i)
			bb.put(ipArray[i]);
		Data data = new Data(dataArray);

		System.out.println(dataArray[0]);
		System.out.println("data: " + Arrays.toString(dataArray));
		System.out.println("ip: " + Arrays.toString(ipArray));

		/* Set ethernet header fields */
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		ether.setSourceMACAddress(sourceMAC.toBytes());
		ether.setPayload(ip);

		ip.setPayload(icmp);
		icmp.setPayload(data);

		System.out.println("*** -> Forwarding packet: " + ether.toString().replace("\n", "\n\t"));
		this.sendPacket(ether, inIface);
		return;
	}

	private void sendEchoReply(Iface inIface, IPv4 ipPacket) {

		/* Get the MACAdresses for the ether header */
		int dstAddr = ipPacket.getSourceAddress();
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
		if (bestMatch == null) {
			System.out.println("bestMatch echo is null");
			return; // drop the echo request
		}
		int nextHop = bestMatch.getGatewayAddress();
		if (nextHop == 0)
			nextHop = dstAddr;
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null) {
			System.out.println("arpEntry echo is null");
			return;
		}

		/* Set ethernet header */
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		/* Set IP header */
		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(ipPacket.getDestinationAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		/* Set the icmp header */
		ICMP icmp = new ICMP();
		icmp.setIcmpType((byte) 0);
		icmp.setIcmpCode((byte) 0);

		/* Set the payloads */
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(ipPacket.getPayload().getPayload()); // may not work

		this.sendPacket(ether, inIface);
	}

	protected void sendArpReply(Ethernet etherPacket, Iface inIface) {
		System.out.println("inside the sendARP method");
		/* Set the ARP header */
		ARP arpIn = (ARP) etherPacket.getPayload();
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REPLY);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		arp.setTargetHardwareAddress(arpIn.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(arpIn.getSenderProtocolAddress());

		/* Set ethernet header */
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(ether.getSourceMACAddress());
		ether.setPayload(arp);
		System.out.println("*** -> Forwarding packet: " + ether.toString().replace("\n", "\n\t"));
		this.sendPacket(ether, inIface);
	}

	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
			return;

		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		if (targetIp == inIface.getIpAddress())
			this.sendArpReply(etherPacket, inIface);
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
			return;

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum) {
			return;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			System.out.println("Received a packet with TTL of 0");
			this.sendICMP(inIface, ipPacket, (byte) 11, (byte) 0);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				/* Need to check the type */
				byte packetProtocol = ipPacket.getProtocol();
				if (packetProtocol == IPv4.PROTOCOL_TCP || packetProtocol == IPv4.PROTOCOL_UDP)
					this.sendICMP(inIface, ipPacket, (byte) 3, (byte) 3);
				else if (packetProtocol == IPv4.PROTOCOL_ICMP) {
					if (((ICMP) ipPacket.getPayload()).getIcmpType() == (byte) 8)
						this.sendEchoReply(inIface, ipPacket);
				}
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("not an IP packet");
			return;
		}

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, send ICMP message
		if (null == bestMatch) {
			this.sendICMP(inIface, ipPacket, (byte) 3, (byte) 0);
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			/* Generate an ARP Request to try to get the correct entry */
			this.sendICMP(inIface, ipPacket, (byte) 3, (byte) 1);

			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}
}
