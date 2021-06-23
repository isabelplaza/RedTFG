/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.ngsdn.tutorial;

import com.google.common.collect.Lists;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.event.Event;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Path;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.ngsdn.tutorial.common.FabricDeviceConfig;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;
import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * App component that configures devices to provide IPv6 routing capabilities
 * across the whole fabric.
 */
@Component(
        immediate = true,
        // *** TODO EXERCISE 5
        // set to true when ready
        enabled = true
)
public class Ipv6SimpleRoutingComponent {

    private static final Logger log = LoggerFactory.getLogger(Ipv6SimpleRoutingComponent.class);

    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;

    private final HostListener hostListener = new InternalHostListener();
    //private final LinkListener linkListener = new InternalLinkListener();
    //private final DeviceListener deviceListener = new InternalDeviceListener();
    private final TopologyListener topologyListener = new InternalTopologyListener();


    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        hostService.addListener(hostListener);
        //linkService.addListener(linkListener);
        //deviceService.addListener(deviceListener);
        topologyService.addListener(topologyListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        //linkService.removeListener(linkListener);
        //deviceService.removeListener(deviceListener);
        topologyService.removeListener(topologyListener);

        log.info("Stopped");
    }

    //--------------------------------------------------------------------------
    // METHODS TO COMPLETE.
    //
    // Complete the implementation wherever you see TODO.
    //--------------------------------------------------------------------------


    /**
     * Creates a flow rule for the L2 table mapping the given next hop MAC to
     * the given output port.
     * <p>
     * This is called by the routing policy methods below to establish L2-based
     * forwarding inside the fabric, e.g., when deviceId is a leaf switch and
     * nextHopMac is the one of a spine switch.
     *
     * @param deviceId   the device
     * @param nexthopMac the next hop (destination) mac
     * @param outPort    the output port
     */
    private FlowRule createL2NextHopRule(DeviceId deviceId, MacAddress nexthopMac,
                                         PortNumber outPort) {

        // *** TODO EXERCISE 5
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        final String tableId = "IngressPipeImpl.l2_exact_table";
        final PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                        nexthopMac.toBytes())
                .build();


        final PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_egress_port"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("port_num"),
                        outPort.toLong()))
                .build();
        // ---- END SOLUTION ----

        return Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
    }


    private void setSwitchId(DeviceId deviceId, int sw_id) {

        log.info("Setting sw_id {}",sw_id);
        final String tableId = "IngressPipeImpl.sw_id_table";
        final int ETHERTYPE_IPV4 = 0x0800;
        final int MASK = 0xFFFF;
        final PiCriterion match = PiCriterion.builder()
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"),
                        ETHERTYPE_IPV4,MASK)
                .build();

        final PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_sw_id"))
                .withParameter(new PiActionParam(
                        PiActionParamId.of("sw_id"),
                        sw_id))
                .build();

        FlowRule flowRuleSwID = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);
        flowRuleService.applyFlowRules(flowRuleSwID);
    }

    private void cloneToCollector(DeviceId deviceId) {
        final long COLLECTOR_PORT_ID = 4;
        PortNumber collectorPort = PortNumber.portNumber(COLLECTOR_PORT_ID);
        final int COLLECTOR_CLONE_SESSION_ID = 90;

        final GroupDescription cloneGroupCollector = Utils.buildCloneGroup(
                appId,
                deviceId,
                COLLECTOR_CLONE_SESSION_ID,
                // Ports where to clone the packet.
                // Just controller in this case.
                Collections.singleton(collectorPort));

        groupService.addGroup(cloneGroupCollector);

    }


    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of topology events used to obtain the paths between
     * two given hosts.
     */
    private class InternalTopologyListener implements TopologyListener {
        @Override
        public void event(TopologyEvent event) {

        }
    }

    /**
     * Listener of host events which triggers configuration of routing rules on
     * the device where the host is attached.
     */
    class InternalHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                    break;
                case HOST_REMOVED:
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts:
                    // how to support host moved/removed events?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            Host host = event.subject();
            DeviceId deviceId = host.location().deviceId();
            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}, deviceId={}, port={}",
                        event.type(), host.id(), deviceId, host.location().port());
            });
        }
    }


    //--------------------------------------------------------------------------
    // ROUTING POLICY METHODS
    //
    // Called by event listeners, these methods implement the actual routing
    // policy, responsible of computing paths and creating ECMP groups.
    //--------------------------------------------------------------------------


    /**
     * Selects a path from the given set that does not lead back to the
     * specified port if possible.
     */
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        log.info("PICK FORWARD PATH: Paths size: {}", paths.size());
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }

    private void setUpPath(HostId srcId, HostId dstId) {
        Host src = hostService.getHost(srcId);
        Host dst = hostService.getHost(dstId);

        // Check if hosts are located at the same switch
        log.info("Src switch id={} and Dst switch id={}",src.location().deviceId(), dst.location().deviceId());
        if (src.location().deviceId().toString().equals(dst.location().deviceId().toString())) {
            PortNumber outPort = dst.location().port();
            DeviceId devId = dst.location().deviceId();
            FlowRule nextHopRule = createL2NextHopRule(devId, dst.mac(), outPort);
            flowRuleService.applyFlowRules(nextHopRule);
            log.info("Hosts in the same switch");
            return;
        }

        // Get all the available paths between two given hosts
        // A path is a collection of links
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
                src.location().deviceId(),
                dst.location().deviceId());
        if (paths.isEmpty()) {
            // If there are no paths, display a warn and exit
            log.warn("No path found");
            return;
        }

        // Pick a path that does not lead back to where we
        // came from; if no such path,display a warn and exit
        Path path = pickForwardPathIfPossible(paths, src.location().port());
        if (path == null) {
            log.warn("Don't know where to go from here {} for {} -> {}",
                    src.location(), srcId, dstId);
            return;
        }

        // Install rules in the path
        List<Link> pathLinks = path.links();
        for (Link l : pathLinks) {
            PortNumber outPort = l.src().port();
            DeviceId devId = l.src().deviceId();
            FlowRule nextHopRule = createL2NextHopRule(devId,dst.mac(),outPort);
            flowRuleService.applyFlowRules(nextHopRule);
        }
        // Install rule in the last device (where dst is located)
        PortNumber outPort = dst.location().port();
        DeviceId devId = dst.location().deviceId();
        FlowRule nextHopRule = createL2NextHopRule(devId,dst.mac(),outPort);
        flowRuleService.applyFlowRules(nextHopRule);

    }

    /*



    /**
     * Selects a path from the given set that is not the shortest one if possible.

    private Path pickLongerForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        log.info("PICK LONGER FORWARD PATH: Paths size: {}", paths.size());

        if (paths.size() > 1) {
            log.info("There are more than one path available");
            int i = 0;
            for (Path path : paths) {
                if (!path.src().port().equals(notToPort)) {
                    if (i == 1)
                        log.info("Setting the second path of the available paths list");
                        return path;
                }
                log.info("For loop, i: {}", i);
                i++;
            }
            return null;

        } else {
            log.info("There is just one path available");
            for (Path path : paths) {
                if (!path.src().port().equals(notToPort)) {
                    return path;
                }
            }
            return null;

        }
    }

    private void setUpLongerPath(HostId srcId, HostId dstId) {
        Host src = hostService.getHost(srcId);
        Host dst = hostService.getHost(dstId);

        // Check if hosts are located at the same switch
        log.info("Src switch id={} and Dst switch id={}",src.location().deviceId(), dst.location().deviceId());
        if (src.location().deviceId().toString().equals(dst.location().deviceId().toString())) {
            PortNumber outPort = dst.location().port();
            DeviceId devId = dst.location().deviceId();
            FlowRule nextHopRule = createL2NextHopRule(devId, dst.mac(), outPort);
            flowRuleService.applyFlowRules(nextHopRule);
            log.info("Hosts in the same switch");
            return;
        }

        // Get all the available paths between two given hosts
        // A path is a collection of links
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
                src.location().deviceId(),
                dst.location().deviceId());
        log.info("SET UP LONGER PATH: Paths size: {}", paths.size());

        if (paths.isEmpty()) {
            // If there are no paths, display a warn and exit
            log.warn("No path found");
            return;
        }

        // Pick a path that neither leads back to where we came from nor is the shortest one;
        // if no such path, pick a path that does not lead back to where we came from;
        // if no such path, display a warn and exit
        Path path = pickLongerForwardPathIfPossible(paths, src.location().port());
        if (path == null) {
            log.warn("Don't know where to go from here {} for {} -> {}",
                    src.location(), srcId, dstId);
            return;
        }

        // Install rules in the path
        List<Link> pathLinks = path.links();
        for (Link l : pathLinks) {
            PortNumber outPort = l.src().port();
            DeviceId devId = l.src().deviceId();
            FlowRule nextHopRule = createL2NextHopRule(devId,dst.mac(),outPort);
            flowRuleService.applyFlowRules(nextHopRule);
        }
        // Install rule in the last device (where dst is located)
        PortNumber outPort = dst.location().port();
        DeviceId devId = dst.location().deviceId();
        FlowRule nextHopRule = createL2NextHopRule(devId,dst.mac(),outPort);
        flowRuleService.applyFlowRules(nextHopRule);

    }

    */

    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Sets up L2 forwarding of all devices in a path between two given  hosts.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes

        HostId h1Id = HostId.hostId("00:00:00:00:00:1A/None");
        HostId h2Id = HostId.hostId("00:00:00:00:00:1B/None");
        HostId h3Id = HostId.hostId("00:00:00:00:00:1C/None");
        HostId collectorId = HostId.hostId("00:00:00:00:00:1D/None");


        // Set bidirectional path
        setUpPath(h1Id, h2Id);
        setUpPath(h2Id, h1Id);

        //setUpLongerPath(h3Id, collectorId);
        //setUpLongerPath(collectorId, h3Id);
        setUpPath(h3Id, collectorId);
        setUpPath(collectorId, h3Id);
        

        // Set switches' IDs
        //deviceId1 = "device:leaf1";
        DeviceId sw1_id=DeviceId.deviceId("device:leaf1");
        DeviceId sw2_id=DeviceId.deviceId("device:leaf2");
        DeviceId sw3_id=DeviceId.deviceId("device:leaf3");

        setSwitchId(sw1_id, 1);
        setSwitchId(sw2_id, 2);
        setSwitchId(sw3_id, 3);

        cloneToCollector(sw2_id);

    }
}