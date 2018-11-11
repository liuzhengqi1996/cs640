package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;
	private RipTable ripTable;

	/* For queueing while waiting for ARP replies */
	private Map<Integer, Boolean> replyReceived;
	private Map<Integer, LinkedList<Request>> queuedRequests;

	/** ARP cache for the router */
	private ArpCache arpCache;

	public static final int MULTICAST_ADDR = 1276475249;

	/**
	 * Creates a router for a specific host.
	 *
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.replyReceived = new HashMap<Integer, Boolean>();
		this.queuedRequests = new HashMap<Integer, LinkedList<Request>>();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	public Map<Integer, Boolean> getReplyReceived() {
		return this.replyReceived;
	}

	public Map<Integer, LinkedList<Request>> getQueuedRequests() {
		return this.queuedRequests;
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

	public void startRIP() {
		System.out.println("Starting RIP");
		System.out.println("-------------------------------------------------");

		this.ripTable = new RipTable(this.routeTable);

		// Load Router interfaces into RIP Table
		for (Iface iface : this.interfaces.values()) {
			this.ripTable.insert(iface);
		}

		for (Iface iface : this.interfaces.values()) {
			this.sendRipRequest(iface);
		}

		UnsolicitedRipResponse unsolicitedRipResponse = new UnsolicitedRipResponse(this);
		ScheduledExecutorService unsolicitedRipResponseExecutor = Executors.newScheduledThreadPool(1);
		unsolicitedRipResponseExecutor.scheduleAtFixedRate(unsolicitedRipResponse, 10, 10, TimeUnit.SECONDS);

		RipReaper ripReaper = new RipReaper(this.ripTable);
		ScheduledExecutorService ripReaperExecutor = Executors.newScheduledThreadPool(1);
		ripReaperExecutor.scheduleAtFixedRate(ripReaper, 5, 10, TimeUnit.SECONDS);
	}

	private UDP wrapRip(RIPv2 rip) {
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(rip);
		return udp;
	}

	private IPv4 wrapUdp(UDP udp, int sourceIP, int destIP) {
		IPv4 ipv4 = new IPv4();
		ipv4.setTtl((byte) 64);
		ipv4.setProtocol(IPv4.PROTOCOL_UDP);
		ipv4.setSourceAddress(sourceIP);
		ipv4.setDestinationAddress(destIP);
		ipv4.setPayload(udp);
		return ipv4;
	}

	private Ethernet wrapIpv4(IPv4 ipv4, MACAddress sourceMAC, MACAddress destMAC) {
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(sourceMAC.toBytes());
		ether.setDestinationMACAddress(destMAC.toBytes());
		ether.setPayload(ipv4);
		return ether;
	}

	private void sendRipRequest(Iface outIface) {
		System.out.println("Sending RIP Request.");
		RIPv2 req = new RIPv2();
		req.setCommand(RIPv2.COMMAND_REQUEST);
		UDP udp = this.wrapRip(req);
		IPv4 ipv4 = this.wrapUdp(udp, outIface.getIpAddress(), MULTICAST_ADDR);
		Ethernet ether = this.wrapIpv4(ipv4, outIface.getMacAddress(), MACAddress.valueOf("FF:FF:FF:FF:FF:FF"));
		this.sendPacket(ether, outIface);
	}

	private void sendUnsolicitedRipResponse(Iface outIface) {
		System.out.println("Sending unsolicited RIP Response.");
		RIPv2 req = new RIPv2();
		req.setEntries(this.ripTable.entriesList(outIface));
		req.setCommand(RIPv2.COMMAND_RESPONSE);
		UDP udp = this.wrapRip(req);
		IPv4 ipv4 = this.wrapUdp(udp, outIface.getIpAddress(), MULTICAST_ADDR);
		Ethernet ether = this.wrapIpv4(ipv4, outIface.getMacAddress(), MACAddress.valueOf("FF:FF:FF:FF:FF:FF"));
		this.sendPacket(ether, outIface);
	}

	private void sendSolicitedRipResponse(Iface outIface, int destIP, MACAddress destMAC) {
		System.out.println("Sending solicited RIP Response.");
		RIPv2 req = new RIPv2();
		req.setEntries(this.ripTable.entriesList(outIface));
		req.setCommand(RIPv2.COMMAND_RESPONSE);
		UDP udp = this.wrapRip(req);
		IPv4 ipv4 = this.wrapUdp(udp, outIface.getIpAddress(), destIP);
		Ethernet ether = this.wrapIpv4(ipv4, outIface.getMacAddress(), destMAC);
		this.sendPacket(ether, outIface);
	}

	private void handleRipPacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("Handle RIP Packet");
		MACAddress sourceMAC = etherPacket.getSourceMAC();
		IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();
		int sourceIP = ipv4Packet.getSourceAddress();
		UDP udpPacket = (UDP) ipv4Packet.getPayload();
		RIPv2 rip = (RIPv2) udpPacket.getPayload();
		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			// inIface becomes outIface; source address and source mac become dest address and dest mac
			this.sendSolicitedRipResponse(inIface, sourceIP, sourceMAC);
		} else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
			this.ripTable.update(inIface, rip.getEntries());
		}
	}

	class UnsolicitedRipResponse implements Runnable {
		private Router router;

		public UnsolicitedRipResponse(Router router) {
			this.router = router;
		}
		public void run() {
			for (Iface iface : this.router.interfaces.values()) {
				this.router.sendUnsolicitedRipResponse(iface);
			}
		}
	}

	class RipReaper implements Runnable {
		private RipTable ripTable;

		public RipReaper(RipTable ripTable) {
			this.ripTable = ripTable;
		}

		public void run() {
			this.ripTable.purgeStale();
		}
	}

	class ARPThread implements Runnable {
		private Iface outIface;
		private Router caller;
		private int neededIp;
		private Map<Integer, Boolean> replyReceived;
		private Map<Integer, LinkedList<Request>> queuedRequests;

		public ARPThread(Iface outIface, Router caller, int nextHop) {
			this.neededIp = nextHop;
			this.outIface = outIface;
			this.caller = caller;
			this.replyReceived = caller.getReplyReceived();
			this.queuedRequests = caller.getQueuedRequests();
		}

		public void run() {
			System.out.println("running a new ARP thread");
			int requestCount = 0;
			Boolean received = false;
			while (requestCount < 3 && !received) {
				caller.sendArpRequest(neededIp, outIface);
				++requestCount;
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				// Check whether the calling Router has received the reply
				synchronized (this.replyReceived) {
					if (!this.replyReceived.isEmpty() && this.replyReceived.containsKey(neededIp))
						received = this.replyReceived.get(neededIp);
				}
			}
			/* Handle the queued requests for this */
			synchronized (this.replyReceived) {
				if (!this.replyReceived.isEmpty() && this.replyReceived.containsKey(neededIp))
					received = this.replyReceived.get(neededIp);
			}
			System.out.println("Received the reply: " + received);
			/* If we got a reply we can now forward the packets */
			LinkedList<Request> pendingRequests;
			synchronized (this.queuedRequests) {
				pendingRequests = this.queuedRequests.get(neededIp);
			}
			if (received.booleanValue()) {
				for (Request r : pendingRequests) {
					System.out.println("Calling handlePacket on queued request");
					caller.handleQueuedIpPacket(r.etherPacket, r.inIface);
				}
			}
			/* Otherwise send the appropriate ICMP message */
			else {
				for (Request r : pendingRequests) {
					caller.sendICMP(r.inIface, r.etherPacket, (byte) 3, (byte) 1);
				}
			}

			/* Remove the entries from the shared data structures */
			synchronized (this.replyReceived) {
				this.replyReceived.remove(neededIp);
			}
			synchronized (this.queuedRequests) {
				this.queuedRequests.remove(neededIp);
			}
		}
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 *
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));

		/* Let's first see if we have the correct ARP entry. */

		/********************************************************************/
		/* TODO: Handle packets */
		switch (etherPacket.getEtherType()) {
		case Ethernet.TYPE_IPv4:
			IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();
			// System.out.println(ipv4Packet.getProtocol());
			// System.out.println(ipv4Packet.getDestinationAddress());
			// System.out.println(((UDP)ipv4Packet.getPayload()).getDestinationPort());
			if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP &&
					ipv4Packet.getDestinationAddress() == MULTICAST_ADDR &&
					((UDP)ipv4Packet.getPayload()).getDestinationPort() ==  UDP.RIP_PORT) {
				this.handleRipPacket(etherPacket, inIface);
			} else {
				this.handleIpPacket(etherPacket, inIface);
			}
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	public void sendArpRequest(int neededIp, Iface outIface) {
		System.out.println("inside the sendARPRequest method");

		/* Set the broadcast MAC address to an array */
		byte[] broadcastMAC = new byte[6];
		Arrays.fill(broadcastMAC, (byte) 255); // FF:FF:FF:FF:FF:FF

		/* Get the ip address whose MAC we want in byte[] form */
		byte[] Ip = ByteBuffer.allocate(4).putInt(neededIp).array();

		/* Set the ARP header */
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REQUEST);
		arp.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(outIface.getIpAddress());
		arp.setTargetHardwareAddress(new byte[Ethernet.DATALAYER_ADDRESS_LENGTH]);
		arp.setTargetProtocolAddress(Ip);

		/* Set ethernet header */
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(broadcastMAC);
		ether.setPayload(arp);
		System.out.println("*** -> Forwarding packet: " + ether.toString().replace("\n", "\n\t"));
		this.sendPacket(ether, outIface);
	}

	private void sendICMP(Iface inIface, Ethernet etherPacket, byte type, byte code) {
		System.out.println("Inside the sendICMP method");
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();

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
		if (arpEntry == null) {
			System.out.println("arpEntry is null");
			this.findArpEntry(nextHop, bestMatch, etherPacket, inIface);
			return;
		}
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

	private void sendEchoReply(Iface inIface, Ethernet etherPacket) {
		System.out.println("sending an echo reply");

		IPv4 ipPacket = (IPv4)etherPacket.getPayload();

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
			this.findArpEntry(nextHop, bestMatch, etherPacket, inIface);
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
		if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			if (targetIp == inIface.getIpAddress())
				this.sendArpReply(etherPacket, inIface);
			else
				this.forwardIpPacket(etherPacket, inIface);
		} else if (arpPacket.getOpCode() == ARP.OP_REPLY) {
			System.out.println("received reply");

			/* Get the ip addr */
			int senderArpIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			MACAddress senderArpMac = new MACAddress(arpPacket.getSenderHardwareAddress());

			/* add the reply to the arpCache */
			arpCache.insert(senderArpMac, senderArpIp);

			/* Update the shared data structure */
			synchronized (this.replyReceived) {
				if (!this.replyReceived.isEmpty() && this.replyReceived.containsKey(senderArpIp)) {
					this.replyReceived.put(senderArpIp, true);
				}
			}
		}
	}

	private void handleQueuedIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
			return;

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				System.out.println("Packet destined for router interface");
				/* Need to check the type */
				byte packetProtocol = ipPacket.getProtocol();
				if (packetProtocol == IPv4.PROTOCOL_TCP || packetProtocol == IPv4.PROTOCOL_UDP)
					this.sendICMP(inIface, etherPacket, (byte) 3, (byte) 3);
				else if (packetProtocol == IPv4.PROTOCOL_ICMP) {
					if (((ICMP) ipPacket.getPayload()).getIcmpType() == (byte) 8)
						this.sendEchoReply(inIface, etherPacket);
				}
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
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
			System.out.println("Checksum Wrong");
			return;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			System.out.println("Received a packet with TTL of 0");
			this.sendICMP(inIface, etherPacket, (byte) 11, (byte) 0);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				System.out.println("Packet destined for router interface");
				/* Need to check the type */
				byte packetProtocol = ipPacket.getProtocol();
				if (packetProtocol == IPv4.PROTOCOL_TCP || packetProtocol == IPv4.PROTOCOL_UDP)
					this.sendICMP(inIface, etherPacket, (byte) 3, (byte) 3);
				else if (packetProtocol == IPv4.PROTOCOL_ICMP) {
					if (((ICMP) ipPacket.getPayload()).getIcmpType() == (byte) 8)
						this.sendEchoReply(inIface, etherPacket);
				}
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("forwarding an ip packet");

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
			System.out.println("bestMatch == null");
			this.sendICMP(inIface, etherPacket, (byte) 3, (byte) 0);
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			System.out.println("dropping packet because inIface == outIface");
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
			this.findArpEntry(nextHop, bestMatch, etherPacket, inIface);
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	/*Called when the arp cache doesn't have a needed entry. Creates a thread which will send ARP
	 * request in an effort to add the needed arp entry.*/
	private void findArpEntry(int neededIp, RouteEntry bestMatch, Ethernet etherPacket, Iface inIface) {
		/* Check if the ARP request has already been made. */
		synchronized (this.replyReceived) {
			/* if it has, add the request to the queue */
			if (this.replyReceived.containsKey(neededIp)) {
				this.queuedRequests.get(neededIp).add(new Request(etherPacket, inIface));
				System.out.println("ARP thread already exists queueing new request");
			}
			/* Otherwise created a new thread to generate the request */
			else {
				System.out.println("Creating thread to issue ARP requests");
				this.replyReceived.put(neededIp, false);
				this.queuedRequests.put(neededIp, new LinkedList<Request>());
				this.queuedRequests.get(neededIp).add(new Request(etherPacket, inIface));
				Thread t = new Thread(new ARPThread(bestMatch.getInterface(), this, neededIp));
				t.start();
			}
		}
		return;
	}
}

/* Class to group together requests that must be queued during ARP requests */
class Request {
	Ethernet etherPacket; // the packet itself
	Iface inIface; // interface the request was recieved on

	Request(Ethernet etherPacket, Iface inIface) {
		this.etherPacket = etherPacket;
		this.inIface = inIface;
	}
}
