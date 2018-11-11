package edu.wisc.cs.sdn.vnet.rt;

import java.util.*;
import java.util.concurrent.*;

import net.floodlightcontroller.packet.*;
import edu.wisc.cs.sdn.vnet.*;


public class RipTable {
  private RouteTable routeTable;
  private HashMap<Integer, HashMap<Integer, RipTableEntry>> entries;
  public static final int TIMEOUT_SECONDS = 30;

  public RipTable(RouteTable routeTable) {
    this.routeTable = routeTable;
    this.entries = new HashMap<Integer, HashMap<Integer, RipTableEntry>>();
  }

  void insert(int metric, int address, int gateway, int subnet, Iface iface) {
    RipTableEntry newEntry = new RipTableEntry(iface, address, gateway, subnet, metric);
    this.insert(newEntry);
  }

  void insert(RipTableEntry newEntry) {
    int metric = newEntry.getMetric();
    int address = newEntry.getAddress();
    int gateway = newEntry.getGatewayAddress();
    int subnet = newEntry.getSubnetMask();
    Iface iface = newEntry.getIface();
    synchronized(this.entries) {
      this.entries.putIfAbsent(address, new HashMap<Integer, RipTableEntry>());
      this.entries.get(address).put(subnet, newEntry);
      if (this.routeTable.find(address, gateway)) {
        this.routeTable.insert(address, gateway, subnet, iface);
      } else {
        this.routeTable.insert(address, gateway, subnet, iface);
      }
    }
  }

  void remove(RipTableEntry entry) {
    int address = entry.getAddress();
    int subnet = entry.getSubnetMask();
    synchronized(this.entries) {
      this.entries.get(address).remove(subnet);
      this.routeTable.remove(address, subnet);
    }
  }

  void purgeStale() {
    for (HashMap<Integer, RipTableEntry> entry : this.entries.values()) {
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
    newTableEntry.incrementMetric();
    int address = newTableEntry.getAddress();
    int subnet = newTableEntry.getSubnetMask();
    synchronized(this.entries) {
      this.entries.putIfAbsent(address, new HashMap<Integer, RipTableEntry>());
      if (this.entries.get(address).containsKey(subnet)) {
        RipTableEntry oldEntry = this.entries.get(address).get(subnet);
        if (newEntry.getMetric() < oldEntry.getMetric()) {
          this.entries.get(address).put(subnet, newTableEntry);

        }
      } else {
        HashMap<Integer, RipTableEntry> newMap = this.entries.getOrDefault(address, new HashMap<Integer, RipTableEntry>());
        newMap.put(subnet, newTableEntry);
        this.entries.put(address, newMap);
      }
    }
  }

  public String toString() {
    String str = "";
    for (HashMap<Integer, RipTableEntry> entry : this.entries.values()) {
      // HashMap<Integer, RipTableEntry> entry = this.entries.get(k);
      for (RipTableEntry tableEntry : entry.values()) {
        // RipTableEntry tableEntry = entry.get(j);
        str = tableEntry.getAddress() + "\t" + tableEntry.getSubnetMask() + "\t" + tableEntry.getMetric();
      }
    }
    return str;
  }

  /* Class to group together  */
  private class RipTableEntry {
  	RIPv2Entry ripEntry;
  	long timeout;
    Iface iface;

    public RipTableEntry(Iface iface, int address, int gateway, int subnet, int metric) {
      this.iface = iface;
      this.ripEntry = new RIPv2Entry(address, subnet, metric);
      this.ripEntry.setNextHopAddress(gateway);
      this.refreshTimeout();
    }

    public RipTableEntry(Iface iface, RIPv2Entry ripv2Entry) {
      this.iface = iface;
      this.ripEntry = ripv2Entry;
      this.refreshTimeout();
    }

    void incrementMetric() {
      this.ripEntry.setMetric(this.getMetric());
    }

  	boolean isStale() {
  		if (!this.isPermanent() && System.currentTimeMillis() > this.timeout) {
  			return true;
  		}
  		return false;
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
  		return this.ripEntry.getNextHopAddress();
  	}

    boolean isPermanent() {
      return this.getMetric() == 0;
    }

    Iface getIface() {
      return this.iface;
    }
  }

}
