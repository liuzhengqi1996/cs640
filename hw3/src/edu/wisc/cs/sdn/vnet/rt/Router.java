package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4 ) {
			System.out.println("return");
			return;
		}

		IPv4 payload = (IPv4) etherPacket.getPayload();
		short checksum = payload.getChecksum();
		payload.setChecksum((short)0);
		payload.serialize();

		if (checksum != payload.getChecksum()) {
			System.out.println("bad checksum; dropping");
			return;
		}

		int ttl = payload.getTtl() - 1;
		if (ttl < 1) {
			System.out.println("TTL < 1; dropping");
			return;
		}
		payload.setTtl((byte) ttl);
		payload.setChecksum((short)0);
		payload.serialize();

		for (Iface iface : this.interfaces.values()) {
			if (payload.getDestinationAddress() == iface.getIpAddress()) {
				System.out.println("Matched Iface; dropping");
				return;
			}
		}

		RouteEntry nextHop = this.routeTable.lookup(payload.getDestinationAddress());
		if (nextHop == null) {
			System.out.println("next hop is null; dropping");
			return;
		}

		System.out.println(nextHop);
		System.out.println(this.arpCache);

		ArpEntry destinationARP;
		if (nextHop.getGatewayAddress() != 0) {
			System.out.println("Gateway is next.");
			destinationARP = this.arpCache.lookup(nextHop.getGatewayAddress());
		} else {
			destinationARP = this.arpCache.lookup(payload.getDestinationAddress());
		}

		if (destinationARP == null) {
			System.out.println("destination ARP is null; dropping");
			return;
		}
		System.out.println("Destination ARP");
		System.out.println(destinationARP);
		MACAddress destinationMAC = destinationARP.getMac();
		Iface outgoingIface = nextHop.getInterface();

		etherPacket.setSourceMACAddress(outgoingIface.getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(destinationMAC.toBytes());

		System.out.println("etherPacket");
		System.out.println(etherPacket);

		this.sendPacket(etherPacket, outgoingIface);

		/********************************************************************/
	}
}
