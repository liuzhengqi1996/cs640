#!/bin/bash
ovs-vsctl set bridge s1 protocols=OpenFlow10
ovs-vsctl set bridge s2 protocols=OpenFlow10
ovs-vsctl set bridge s3 protocols=OpenFlow10
ovs-vsctl set bridge s4 protocols=OpenFlow10
ovs-vsctl set bridge r1 protocols=OpenFlow10
ovs-vsctl set bridge r2 protocols=OpenFlow10
ovs-vsctl set bridge r3 protocols=OpenFlow10
ovs-vsctl set bridge r4 protocols=OpenFlow10
python ./pox/pox.py cs640.ofhandler cs640.vnethandler
