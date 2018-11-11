package edu.wisc.cs.sdn.vnet.rt;

import java.util.*;
import java.util.concurrent.*;

import net.floodlightcontroller.packet.*;
import edu.wisc.cs.sdn.vnet.*;

public class RipTable {
  private RouteTable routeTable;
  private ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, RipTableEntry>> entries;
  public static final int TIMEOUT_SECONDS = 30;

  public RipTable(RouteTable routeTable) {
    this.routeTable = routeTable;
    this.entries = new ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, RipTableEntry>>();
  }

  void insert(Iface iface) {
    RipTableEntry newEntry = new RipTableEntry(iface);
    this.insert(newEntry);
  }

  void insert(RipTableEntry newTableEntry) {
    int metric = newTableEntry.getMetric();
    int address = newTableEntry.getAddress();
    int gateway = newTableEntry.getGatewayAddress();
    int subnet = newTableEntry.getSubnetMask();
    Iface iface = newTableEntry.getIface();
    this.entries.putIfAbsent(address & subnet, new ConcurrentHashMap<Integer, RipTableEntry>());
    this.entries.get(address & subnet).put(subnet, newTableEntry);
    if (this.routeTable.contains(address & subnet, gateway)) {
      this.routeTable.update(address & subnet, gateway, subnet, iface);
    } else {
      this.routeTable.insert(address & subnet, gateway, subnet, iface);
    }
  }

  void remove(RipTableEntry entry) {
    int address = entry.getAddress();
    int subnet = entry.getSubnetMask();
    this.entries.get(address & subnet).remove(subnet);
    this.routeTable.remove(address & subnet, subnet);
  }

  void purgeStale() {
    for (ConcurrentHashMap<Integer, RipTableEntry> entry : this.entries.values()) {
      for (RipTableEntry tableEntry : entry.values()) {
        if (tableEntry.isStale()) {
          this.remove(tableEntry);
        }
      }
    }
  }

  void update(Iface iface, List<RIPv2Entry> newEntries) {
    for (RIPv2Entry newEntry : newEntries) {
      this.update(iface, newEntry);
    }
  }

  void update(Iface iface, RIPv2Entry newEntry) {
    RipTableEntry newTableEntry = new RipTableEntry(iface, newEntry);
    newTableEntry.incrementMetric(); // this is for adding distance
    int address = newTableEntry.getAddress();
    int subnet = newTableEntry.getSubnetMask();
    this.entries.putIfAbsent(address & subnet, new ConcurrentHashMap<Integer, RipTableEntry>());
    if (this.entries.get(address & subnet).containsKey(subnet)) {
      RipTableEntry oldEntry = this.entries.get(address & subnet).get(subnet);
      if (newTableEntry.getMetric() < oldEntry.getMetric()) {
        this.insert(newTableEntry);
      } else if (newTableEntry.equals(oldEntry)) {
        oldEntry.refreshTimeout(); // refresh the timeout if they are the same entry
      }
    } else {
      this.insert(newTableEntry);
    }
    System.out.println(this.toString());
    System.out.println(this.routeTable.toString());
  }

  List<RIPv2Entry> entriesList(Iface iface) {
    List<RIPv2Entry> list = new LinkedList<RIPv2Entry>();
    for (ConcurrentHashMap<Integer, RipTableEntry> entry : this.entries.values()) {
      for (RipTableEntry tableEntry : entry.values()) {
        RIPv2Entry newRipEntry = tableEntry.getEntryClone();
        newRipEntry.setNextHopAddress(iface.getIpAddress());
        list.add(newRipEntry);
      }
    }
    return list;
  }

  public String toString() {
    System.out.println(this.entries.values());
    String str = "Destination\tSubnet Mask\tMetric\tTimeout\n";
    for (ConcurrentHashMap<Integer, RipTableEntry> entry : this.entries.values()) {
      for (RipTableEntry tableEntry : entry.values()) {
        str += IPv4.fromIPv4Address(tableEntry.getAddress()) + "\t" + IPv4.fromIPv4Address(tableEntry.getSubnetMask()) + "\t" + tableEntry.getMetric() + "\t" + tableEntry.timeoutFromNow();
      }
      str += "\n";
    }
    return str;
  }

  /* Class to group together  */
  private class RipTableEntry {
  	RIPv2Entry ripEntry;
  	long timeout;
    Iface iface;

    public RipTableEntry(Iface iface) {
      this.iface = iface;
      this.ripEntry = new RIPv2Entry(iface.getIpAddress(), iface.getSubnetMask(), 0);
      this.ripEntry.setNextHopAddress(0);
      this.refreshTimeout();
    }

    public RipTableEntry(Iface iface, RIPv2Entry ripv2Entry) {
      this.iface = iface;
      this.ripEntry = ripv2Entry;
      this.refreshTimeout();
    }

    public boolean equals(RipTableEntry entry) {
      if (this.getAddress() != entry.getAddress()) {
        return false;
      }
      if (this.getSubnetMask() != entry.getSubnetMask()) {
        return false;
      }
      if (this.getGatewayAddress() != entry.getGatewayAddress()) {
        return false;
      }
      if (!this.getIface().equals(entry.getIface())) {
        return false;
      }
      if (this.getMetric() != entry.getMetric()) {
        return false;
      }
      return true;
    }

    void incrementMetric() {
      this.ripEntry.setMetric(this.getMetric() + 1);
    }

  	boolean isStale() {
  		if (!this.isPermanent() && System.currentTimeMillis() > this.timeout) {
  			return true;
  		}
  		return false;
  	}

    RIPv2Entry getEntry() {
      return this.ripEntry;
    }

    RIPv2Entry getEntryClone() {
      return new RIPv2Entry(this.getAddress(), this.getSubnetMask(), this.getMetric());
    }

    void refreshTimeout() {
      this.timeout = System.currentTimeMillis() + TIMEOUT_SECONDS * 1000;
    }

  	int getAddress() {
  		return this.ripEntry.getAddress();
  	}

  	int getSubnetMask() {
  		return this.ripEntry.getSubnetMask();
  	}

  	int getMetric() {
  		return this.ripEntry.getMetric();
  	}

  	int getGatewayAddress() {
      if (this.getMetric() == 0) {
        return 0;
      }
  		return this.ripEntry.getNextHopAddress();
  	}

    boolean isPermanent() {
      return this.getMetric() == 0;
    }

    Iface getIface() {
      return this.iface;
    }

    int timeoutFromNow() {
      return (int)((this.timeout - System.currentTimeMillis()) / 1000);
    }
  }

}
