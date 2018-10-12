package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.*;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.*;


/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device {
	
	/*The Switch Table. It groups MAC address with a class that groups together
	 * a timeout value and a port name.*/
	Map<MACAddress, SwitchTableEntry> SwitchTable;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile) {
		super(host,logfile);
		
		/*The LinkedHashMap must be synchronized since multiple threads may try to
		 * act on it simultaneously.*/
		SwitchTable = Collections.synchronizedMap(new HashMap<MACAddress
												  , SwitchTableEntry>());
		
		new SwitchTableTimer(); //Start the switch table update thread
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		MACAddress srcMac = etherPacket.getSourceMAC();
		MACAddress destMac = etherPacket.getDestinationMAC();
		
		/*First handle the src address (i.e. check if it is already in the table.
		 * if so, update the timeout; if not, add it.)*/
		if(SwitchTable.containsKey(srcMac)
			&& SwitchTable.get(srcMac).portname.getName().equals(inIface.getName())) {
			SwitchTable.get(srcMac).reset();
		}
		else {
			SwitchTable.put(srcMac, new SwitchTableEntry(inIface));
		}
		
		/*Next, Check if the destination is already in the switch table:
		 * if it is, forward it to the correct port; if not, broadcast.*/
		if(SwitchTable.containsKey(destMac)) {
			sendPacket(etherPacket, SwitchTable.get(destMac).portname);
		}
		else {
			interfaces.forEach((name, iface) -> {
				sendPacket(etherPacket, iface);
			});
		}
	}
	
	/*This class will act as the update thread for the switch table. It's 
	 * run method will execute every second to check if any of the switch
	 * table entries have met the 15 second timeout. If so, they will be
	 * removed from the table.*/
	class SwitchTableTimer {
		Timer switchTableTimer;
		
		public SwitchTableTimer() {
			switchTableTimer = new Timer();
			
			/*Schedule the switch table update to occur every second*/
			switchTableTimer.scheduleAtFixedRate(new UpdateSwitchTable(), 0, 1000);
		}
		
		class UpdateSwitchTable extends TimerTask {
			
			/*This is the method that will run every second to check
			 * whether any switch table entries have timed out.*/
			public void run() {
				/*For each MAC address in the Switch Table, decrement the
				 * timeout value and remove the entry if it has hit zero.*/
				SwitchTable.forEach((k, v) -> {
					SwitchTable.get(k).timeoutCounter--;
					if(SwitchTable.get(k).timeoutCounter <= 0) {
						SwitchTable.remove(k);
					}
				});
			}
		}	
	}
	
	/*This class is used to group together a timeout value with a portname
	 * to be used as the values for the Map that will represent the switch table
	 * (MAC addresses will be used as the keys).*/
	static class SwitchTableEntry {
		public int timeoutCounter; //Time (in seconds) left before timeout
		public Iface portname;    //Name of the port that the MAC Addr was received on.
		
		SwitchTableEntry(Iface name) {
			timeoutCounter = 15; //entries will be removed from the table after 15 secs
			portname = name;
		}
		
		/*Reset the counter in the event that an existing entry
		 * has been received again on the same port.*/
		public void reset() {
			timeoutCounter = 15;
		}
	}
}
