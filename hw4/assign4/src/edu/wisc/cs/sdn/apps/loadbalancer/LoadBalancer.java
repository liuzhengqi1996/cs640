package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.*;
import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.apps.l3routing.L3Routing;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.ARP;
import org.openflow.protocol.*;

import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.ArpServer;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}

	private void installRule(IOFSwitch sw, OFMatch match, OFInstruction... instructions) {
		installRule(sw, match, 0, instructions);
	}

	// priorityModifier adds or subtracts from the default value
	private void installRule(IOFSwitch sw, OFMatch match, int priorityModifier, OFInstruction... instructions) {
		short priority = (short) (SwitchCommands.DEFAULT_PRIORITY + priorityModifier);
		SwitchCommands.removeRules(sw, table, match);
		SwitchCommands.installRule(sw, table, priority, match, Arrays.asList(instructions));
	}

	private void installRuleWithIdleTimeout(IOFSwitch sw, OFMatch match, int priorityModifier, OFInstruction... instructions) {
		short priority = (short) (SwitchCommands.DEFAULT_PRIORITY + priorityModifier);
		SwitchCommands.removeRules(sw, table, match);
		SwitchCommands.installRule(sw, table, priority, match, Arrays.asList(instructions), SwitchCommands.NO_TIMEOUT, LoadBalancer.IDLE_TIMEOUT);
	}

	// Apply actions instruction; pretty sure we need new instances each time which is annoying
	private OFInstruction applyActionsInstruction() {
		OFAction action = new OFActionOutput(OFPort.OFPP_CONTROLLER);
		return new OFInstructionApplyActions(Arrays.asList(action));
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */
		
		/*********************************************************************/

		for (int vip : instances.keySet()) {
			// (1) packets from new connections to each virtual load balancer IP to the controller
			OFMatch matchIpv4 = new OFMatch();
			matchIpv4.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
			matchIpv4.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
			matchIpv4.setNetworkDestination(vip);
			installRule(sw, matchIpv4, 1, applyActionsInstruction());

			// (2) ARP packets to the controller, and
			OFMatch matchArp = new OFMatch();
			matchArp.setDataLayerType(OFMatch.ETH_TYPE_ARP);
			matchArp.setField(OFOXMFieldType.ARP_TPA, vip);
			installRule(sw, matchArp, 1, applyActionsInstruction());
		}

		// (3) all other packets to the next rule table in the switch
		OFMatch matchOther = new OFMatch();
		OFInstruction gotoTableInstruction = new OFInstructionGotoTable(L3Routing.table);
		installRule(sw, matchOther, 0, gotoTableInstruction);

	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       ignore all other packets                                    */
		
		/*********************************************************************/

		switch(ethPkt.getEtherType()) {
			case Ethernet.TYPE_ARP: {
				log.info("Handling ARP");
				ARP arpPkt = (ARP)ethPkt.getPayload();
				if(arpPkt.getOpCode() == ARP.OP_REQUEST) {
					int virtualDestIp = ByteBuffer.wrap(arpPkt.getTargetProtocolAddress()).getInt();
					if (!instances.containsKey(virtualDestIp)) {
						log.warn("Ignore packet because we don't have an instance for virtual address " + virtualDestIp);
						break;
					}
					LoadBalancerInstance instance = instances.get(virtualDestIp);
					byte[] destMACAddress = instance.getVirtualMAC();
//					byte[] destMACAddress = getHostMACAddress(virtualDestIp);

					/*Construct the new packet to send*/
					ARP arpReply = new ARP();
					arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
					arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
					arpReply.setOpCode(ARP.OP_REPLY);
					arpReply.setProtocolAddressLength(arpPkt.getProtocolAddressLength());
					arpReply.setSenderProtocolAddress(virtualDestIp); // virtual ip
					arpReply.setSenderHardwareAddress(destMACAddress); // virtual mac
					arpReply.setHardwareAddressLength(arpPkt.getHardwareAddressLength());
					arpReply.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
					arpReply.setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());

					Ethernet replyPacket = new Ethernet();
					replyPacket.setSourceMACAddress(destMACAddress);
					replyPacket.setDestinationMACAddress(ethPkt.getSourceMACAddress());
					replyPacket.setEtherType(Ethernet.TYPE_ARP);
					replyPacket.setPayload(arpReply);

					SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), replyPacket);
				}
			} break;
			case Ethernet.TYPE_IPv4: {
				log.info("Handling IPv4 TCP");
				IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
				if (ipv4Pkt.getProtocol() != IPv4.PROTOCOL_TCP) {
					log.warn("Ignore packet because it was not TCP");
					break;
				}
				log.info("It's an IPv4 packet.");
				TCP tcpPkt = (TCP) ipv4Pkt.getPayload();
				if (tcpPkt.getFlags() != TCP_FLAG_SYN) {
					log.warn("Ignore packet because it was not TCP SYN");
					break;
				}
				log.info("It's an TCP SYN thingy.");
				int destinationIP = ipv4Pkt.getDestinationAddress();
				if (!instances.containsKey(destinationIP)) {
					log.warn("Ignore packet because we don't have an instance for virtual address " + destinationIP);
					break;
				}
				LoadBalancerInstance instance = instances.get(destinationIP);
				int nextHostIP = instance.getNextHostIP();

				// host to virtual ip
				OFMatch matchToVIP = new OFMatch();
				matchToVIP.setDataLayerType(OFMatch.ETH_TYPE_IPV4); // need to add eth type first!!!
				matchToVIP.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
				matchToVIP.setNetworkSource(ipv4Pkt.getSourceAddress());
				matchToVIP.setNetworkDestination(destinationIP); // instead we send to virtual IP
				matchToVIP.setTransportSource(tcpPkt.getSourcePort());
				matchToVIP.setTransportDestination(tcpPkt.getDestinationPort());

				log.info("destination MAC = "+ new MACAddress(getHostMACAddress(nextHostIP)) +"; destination IP = "+ IPv4.fromIPv4Address(nextHostIP));
				OFAction ipAction = new OFActionSetField(OFOXMFieldType.IPV4_DST, nextHostIP);
				OFAction ethAction = new OFActionSetField(OFOXMFieldType.ETH_DST, this.getHostMACAddress(nextHostIP));
				OFInstruction applyActions = new OFInstructionApplyActions(Arrays.asList(ipAction, ethAction));

				installRuleWithIdleTimeout(sw, matchToVIP, 2, applyActions, new OFInstructionGotoTable(L3Routing.table)); //, gotoTableInstruction);
//				log.info("match: " + matchToVIP);
//				log.info("applyActions: " + applyActions);

				// server to host
				OFMatch matchFromVIP = new OFMatch();
				matchFromVIP.setDataLayerType(OFMatch.ETH_TYPE_IPV4); // need to add eth type first!!!
				matchFromVIP.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
				// the following is essentially reverse of the above
				matchFromVIP.setNetworkSource(nextHostIP);
				matchFromVIP.setNetworkDestination(ipv4Pkt.getSourceAddress());
				matchFromVIP.setTransportSource(tcpPkt.getDestinationPort());
				matchFromVIP.setTransportDestination(tcpPkt.getSourcePort());

				log.info("source MAC = "+ new MACAddress(instance.getVirtualMAC()) +"; source IP = "+ IPv4.fromIPv4Address(destinationIP));

				ipAction = new OFActionSetField(OFOXMFieldType.IPV4_SRC, destinationIP);
				ethAction = new OFActionSetField(OFOXMFieldType.ETH_SRC, instance.getVirtualMAC());
				applyActions = new OFInstructionApplyActions(Arrays.asList(ipAction, ethAction));

				installRuleWithIdleTimeout(sw, matchFromVIP, 2, applyActions, new OFInstructionGotoTable(L3Routing.table)); //, gotoTableInstruction);
//				log.info("match: " + matchFromVIP);
//				log.info("applyActions: " + applyActions);

			} break;
			default: {
				// do nothing!!!
				log.info("Do nothing because it's not part of the project.");
			} break;
		}

		// We don't care about other packets
		log.info("Reached continued...");
		return Command.CONTINUE;
	}

	private List<OFAction> sourceActionList(byte[] mac, int ip) {
		return actionList(OFOXMFieldType.ETH_SRC, mac, OFOXMFieldType.IPV4_SRC, ip);
	}

	private List<OFAction> destinationActionList(byte[] mac, int ip) {
		return actionList(OFOXMFieldType.ETH_DST, mac, OFOXMFieldType.IPV4_DST, ip);
	}

	private List<OFAction> actionList(OFOXMFieldType ethFieldType, byte[] mac, OFOXMFieldType ipv4FieldType, int ip) {
		OFAction actionSetFieldIp = new OFActionSetField(ipv4FieldType, ip);
		OFAction actionSetFieldEth = new OFActionSetField(ethFieldType, mac);
		return Arrays.asList(actionSetFieldIp, actionSetFieldEth);
	}

	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
