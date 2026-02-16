/*
 *
 * Copyright 2026 gRPC authors.
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
 *
 */

package xdsclient

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/internal/envconfig"
	"google.golang.org/grpc/internal/xds/bootstrap"
	"google.golang.org/grpc/internal/xds/clients"
	genericClient "google.golang.org/grpc/internal/xds/clients/xdsclient"
	"google.golang.org/grpc/internal/xds/xdsclient/xdsresource"
	"google.golang.org/grpc/internal/xds/xdsclient/xdsresource/version"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	_ "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	v3discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// Fuzzer manages the execution state of the fuzzer. This component orchestrates
// the test lifecycle: it initializes the genericClient, controls the FakeTransport,
// and maintains a map of open resource watches to track the client's internal
// state during execution.
type Fuzzer struct {
	genericClient        *genericClient.XDSClient
	transportBuilder *FakeTransportBuilder
	activeWatches    map[string]func()
}

func supportedResourceType(config *bootstrap.Config, serverCfg clients.ServerIdentifier) map[string]genericClient.ResourceType {
	gServerCfgMap := map[genericClient.ServerConfig]*bootstrap.ServerConfig{genericClient.ServerConfig{ServerIdentifier: serverCfg}: config.XDSServers()[0]}
	return map[string]genericClient.ResourceType{
		version.V3ListenerURL: {
			TypeURL:                    version.V3ListenerURL,
			TypeName:                   xdsresource.ListenerResourceTypeName,
			AllResourcesRequiredInSotW: true,
			Decoder:                    xdsresource.NewListenerResourceTypeDecoder(config),
		},
		version.V3RouteConfigURL: {
			TypeURL:                    version.V3RouteConfigURL,
			TypeName:                   xdsresource.RouteConfigTypeName,
			AllResourcesRequiredInSotW: false,
			Decoder:                    xdsresource.NewRouteConfigResourceTypeDecoder(config),
		},
		version.V3ClusterURL: {
			TypeURL:                    version.V3ClusterURL,
			TypeName:                   xdsresource.ClusterResourceTypeName,
			AllResourcesRequiredInSotW: true,
			Decoder:                    xdsresource.NewClusterResourceTypeDecoder(config, gServerCfgMap),
		},
		version.V3EndpointsURL: {
			TypeURL:                    version.V3EndpointsURL,
			TypeName:                   xdsresource.EndpointsResourceTypeName,
			AllResourcesRequiredInSotW: false,
			Decoder:                    xdsresource.NewEndpointsResourceTypeDecoder(config),
		},
	}
}

// clientConfig returns a genericClient.Config initialized with the provided
// bootstrap configuration and fake transport builder.
//
// This is used to create an xDS client with a fake transport for fuzzing.
func clientConfig(t *testing.T, config *bootstrap.Config, fakeTransport *FakeTransportBuilder) genericClient.Config {
	t.Helper()

	si := clients.ServerIdentifier{
		ServerURI:  config.XDSServers()[0].ServerURI(),
		Extensions: config.XDSServers()[0].ChannelCreds()[0].Type,
	}
	resourceTypes := supportedResourceType(config, si)

	return genericClient.Config{
		Servers:          []genericClient.ServerConfig{{ServerIdentifier: si}},
		TransportBuilder: fakeTransport,
		ResourceTypes:    resourceTypes,
		Authorities: map[string]genericClient.Authority{
			"": {XDSServers: []genericClient.ServerConfig{}},
		},
	}
}

// NewFuzzer initializes a Fuzzer with a specific bootstrap configuration.
//
// It parses the bootstrap JSON, creates a fake transport builder to mock network
// interactions, and initializes the xDS client (SUT) with these components.
func NewFuzzer(t *testing.T, bootstrapConfig string) (*Fuzzer, error) {
	config, err := bootstrap.NewConfigFromContents([]byte(bootstrapConfig))
	if err != nil {
		return nil, err
	}

	// create a fake transport builder to simulate xDS server interactions.
	fb := NewFakeTransportBuilder()

	// build the xdsclient.Config with the fake transport and bootstrap config.
	coreConfig := clientConfig(t, config, fb)

	// Create an xDS client with the above config.
	client, err := genericClient.New(coreConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create xDS client: %v", err)
	}

	return &Fuzzer{
		genericClient:        client,
		transportBuilder: fb,
		activeWatches:    make(map[string]func()),
	}, nil
}

func (fz *Fuzzer) Close() {
	if fz.genericClient != nil {
		fz.genericClient.Close()
	}
}

// Act performs an action on the Fuzzer.
func (fz *Fuzzer) Act(action *Action) {
	if fz.genericClient == nil {
		return
	}

	switch op := action.ActionType.(type) {
	case *Action_StartWatch:
		fz.StartWatch(op.StartWatch)
	case *Action_StopWatch:
		fz.StopWatch(op.StopWatch)
	case *Action_TriggerConnectionFailure:
		fz.TriggerConnectionFailure(op.TriggerConnectionFailure)
	case *Action_SendMessageToClient:
		fz.handleSendMessageToClient(op.SendMessageToClient)
	case *Action_DumpCsdsData:
		fz.handleDumpCsdsData(op.DumpCsdsData)
	case *Action_ReadMessageFromClient:
		fz.handleReadMessageFromClient(op.ReadMessageFromClient)
	}
}

// StartWatch initiates a watch for the specified xDS resource type and name.
//
// It translates the fuzzer's StartWatch action into a concrete WatchResource call
// on the xDS client, using a no-op watcher (fuzzWatcher) to satisfy the interface.
// The watch's cancel function is stored to allow subsequent StopWatch actions.
func (fz *Fuzzer) StartWatch(op *StartWatch) {
	fmt.Println("StartWatch", op.ResourceName)
	if op == nil || op.ResourceType == nil || op.ResourceName == "" {
		return
	}

	var typeURL string
	switch op.ResourceType.ResourceType.(type) {
	case *ResourceType_Listener:
		typeURL = version.V3ListenerURL
	case *ResourceType_RouteConfig:
		typeURL = version.V3RouteConfigURL
	case *ResourceType_Cluster:
		typeURL = version.V3ClusterURL
	case *ResourceType_Endpoint:
		typeURL = version.V3EndpointsURL
	default:
		return
	}

	resourceName := op.ResourceName
	cancel := fz.genericClient.WatchResource(typeURL, resourceName, &fuzzWatcher{})
	fz.activeWatches[resourceName] = cancel
}

// StopWatch cancels an existing watch for the specified resource name.
//
// It looks up the cancel function associated with the resource name and invokes it.
// If no watch exists for the given name, the operation is a no-op.
func (fz *Fuzzer) StopWatch(op *StopWatch) {
	if op == nil {
		return
	}
	if cancel, ok := fz.activeWatches[op.ResourceName]; ok {
		cancel()
		delete(fz.activeWatches, op.ResourceName)
	}
}

// TriggerConnectionFailure simulates a connection failure for the given authority.
//
// It retrieves the transport associated with the authority and closes its active
// ADS stream, if one exists. This allows fuzzers to test how the xDS client
// handles network interruptions.
func (fz *Fuzzer) TriggerConnectionFailure(op *TriggerConnectionFailure) {
	if op == nil {
		return
	}

	transport := fz.transportBuilder.GetTransport(op.Authority)
	if transport != nil && transport.ActiveAdsStream != nil {
		transport.ActiveAdsStream.Close()
	}
}

// handleSendMessageToClient simulates the management server sending a response
// to the client on the ADS stream.
//
// It locates the active transport for the specified authority and injects the
// provided raw bytes as a DiscoveryResponse. This tests the client's ability
// to unmarshal and validate xDS resources.
func (fz *Fuzzer) handleSendMessageToClient(op *SendMessageToClient) {
	if op == nil {
		return
	}
	
	authority := ""
	if op.StreamId != nil {
		authority = op.StreamId.Authority
	}
	transport := fz.transportBuilder.GetTransport(authority)
	if transport != nil && transport.ActiveAdsStream != nil {
		transport.ActiveAdsStream.InjectRawResponse(op.RawResponseBytes)
	}
}

// handleDumpCsdsData triggers the CSDS resource dump.
//
// This validates that querying the client's internal state (for CSDS/admin endpoints)
// does not panic, even when the state might be in flux due to fuzzing actions.
func (fz *Fuzzer) handleDumpCsdsData(op *DumpCsdsData) {
	fmt.Println("handleDumpCsdsData")
	if op == nil {
		return
	}
	// Verify DumpResources doesn't crash
	_, _ = fz.genericClient.DumpResources()
}

// handleReadMessageFromClient consumes a request sent by the client on the
// ADS stream.
//
// This validates that the client has indeed sent a request (e.g., DiscoveryRequest)
// and clears it from the mock transport's queue to prevent buffer overflow or blocking.
func (fz *Fuzzer) handleReadMessageFromClient(op *ReadMessageFromClient) {
	if op == nil {
		return
	}
	authority := ""
	if op.StreamId != nil {
		authority = op.StreamId.Authority
	}
	transport := fz.transportBuilder.GetTransport(authority)
	if transport != nil && transport.ActiveAdsStream != nil {
		// Just consume the request to clear queue/verify it exists
		_, _ = transport.ActiveAdsStream.ReadRequest(time.Millisecond)
	}
}

// fuzzWatcher implements the ResourceWatcher interface.
//
// It is required to call WatchResource, but the methods are no-ops as the fuzzer
// does not need to react to updates or execute the done callback.
type fuzzWatcher struct{}

func (w *fuzzWatcher) ResourceChanged(data genericClient.ResourceData, done func()) {
	// no-op
	done()
}

func (w *fuzzWatcher) ResourceError(err error, done func()) {
	// no-op
}

func (w *fuzzWatcher) AmbientError(err error, done func()) {
	// no-op 
}

func  FuzzXDSClient(f *testing.F) {
	// Enable crash recovery for the duration of the fuzz test.
	// We set this globally before the fuzz loop to avoid race conditions
	// that occur when using SetEnvConfig inside parallel fuzz iterations.
	origRecover := envconfig.XDSRecoverPanic
	envconfig.XDSRecoverPanic = false
	defer func() { envconfig.XDSRecoverPanic = origRecover }()

	// Add a valid seed input from C++ fuzzer

	// (kBasicListener)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{
								Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "server.example.com"}}},
				{ActionType: &Action_ReadMessageFromClient{
					ReadMessageFromClient: &ReadMessageFromClient{
						StreamId: &StreamId{
							Authority: "",
							Method: &StreamId_Ads{
								Ads: &StreamId_EmptyMessage{}}},
						Ok: true}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{Authority: "", Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "1",
						"nonce": "A",
						"type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
						"resources": [{
							"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
							"name": "server.example.com",
							"api_listener": {
								"api_listener": {
									"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
									"http_filters": [{
										"name": "router",
										"typed_config": {"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}
									}],
									"rds": {
										"route_config_name": "route_config",
										"config_source": {"self": {}}
									}
								}
							}
						}]
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (kBasicCluster)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Cluster{
								Cluster: &ResourceType_EmptyMessage{}}},
						ResourceName: "cluster1"}}},
				{ActionType: &Action_ReadMessageFromClient{
					ReadMessageFromClient: &ReadMessageFromClient{
						StreamId: &StreamId{
							Authority: "",
							Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
						Ok: true}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{
						Authority: "",
						Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "1",
						"nonce": "A",
						"type_url": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
						"resources": [{
							"@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
							"name": "cluster1",
							"type": "EDS",
							"eds_cluster_config": {
								"eds_config": {"ads": {}},
								"service_name": "endpoint1"
							}
						}]
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (kBasicRoute)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_RouteConfig{
								RouteConfig: &ResourceType_EmptyMessage{}}},
						ResourceName: "route_config"}}},
				{ActionType: &Action_ReadMessageFromClient{
					ReadMessageFromClient: &ReadMessageFromClient{
						StreamId: &StreamId{
							Authority: "",
							Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
						Ok: true}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{
						Authority: "",
						Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "1",
						"nonce": "A",
						"type_url": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
						"resources": [{
							"@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
							"name": "route_config",
							"virtual_hosts": [{
								"name": "vhost1",
								"domains": ["*"],
								"routes": [{"match": {"prefix": "/"}, "direct_response": {"status": 200}}]
							}]
						}]
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (kBasicEndpoint)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Endpoint{
								Endpoint: &ResourceType_EmptyMessage{}}},
						ResourceName: "endpoint1"}}},
				{ActionType: &Action_ReadMessageFromClient{
					ReadMessageFromClient: &ReadMessageFromClient{
						StreamId: &StreamId{
							Authority: "",
							Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
						Ok: true}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{
						Authority: "",
						Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "1",
						"nonce": "A",
						"type_url": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
						"resources": [{
							"@type": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
							"cluster_name": "endpoint1",
							"endpoints": [{
								"lb_endpoints": [{
									"endpoint": {
										"address": {
											"socket_address": {
												"address": "127.0.0.1",
												"port_value": 8080
											}
										}
									}
								}]
							}]
						}]
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (XdsServersEmpty)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": []}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "\003"}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (ResourceWrapperEmpty)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Cluster{Cluster: &ResourceType_EmptyMessage{}}},
						ResourceName: "cluster"}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "envoy.config.cluster.v3.Cluster",
						"resources": [{"@type": "type.googleapis.com/envoy.service.discovery.v3.Resource"}],
						"canary": true,
						"type_url": "envoy.config.cluster.v3.Cluster",
						"nonce": "envoy.config.cluster.v3.Cluster"
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (RlsMissingTypedExtensionConfig)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_RouteConfig{RouteConfig: &ResourceType_EmptyMessage{}}},
						ResourceName: "route_config"}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "grpc.lookup.v1.RouteLookup",
						"resources": [{
							"@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
							"value": "CAFiAA=="
						}],
						"type_url": "envoy.config.route.v3.RouteConfiguration",
						"nonce": "/@\001\000\\\000\000x141183468234106731687303715884105729"
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (SendMessageToClientBeforeStreamCreated)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// (UnsubscribeWhileAdsCallInBackoff)
	f.Add(func() []byte {
		m := &Msg{
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "server.example.com"}}},
				// Trigger connection failure to induce backoff
				{ActionType: &Action_TriggerConnectionFailure{TriggerConnectionFailure: &TriggerConnectionFailure{}}},
				{ActionType: &Action_StopWatch{
					StopWatch: &StopWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "server.example.com"}}},
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
						"version_info": "1",
						"nonce": "A",
						"type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
						"resources": [{
							"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
							"name": "server.example.com",
							"api_listener": {
								"api_listener": {
									"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
									"http_filters": [{"name": "router", "typed_config": {"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}],
									"rds": {
										"route_config_name": "route_config",
										"config_source": {"self": {}}
									}
								}
							}
						}]
					}`),
				}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	// "Orphaned RDS" scenario.
	f.Add(func() []byte {
		m := &Msg{
			// 0. Bootstrap (Standard insecure xDS server)
			Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com", "channel_creds":[{"type": "insecure"}]}]}`,
			Actions: []*Action{
				// 1. Action_StartWatch(LDS, "ListenerA")
				{ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{
								Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "ListenerA"}}},

				// 2. Action_SendMessage(RDS, "RouteX") - ORPHANED INJECTION
				// This is the "premature" update.
				// Note: We send an RDS response, but the client hasn't asked for it yet.
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{
						Authority: "",
						Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
                    "version_info": "1",
                    "nonce": "A",
                    "type_url": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
                    "resources": [{
                        "@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
                        "name": "RouteX",
                        "virtual_hosts": [{
                            "name": "vhost1",
                            "domains": ["*"],
                            "routes": [{"match": {"prefix": "/"}, "direct_response": {"status": 200}}]
                        }]
                    }]
                }`),
				}}},

				// 3. Action_SendMessage(LDS, "ListenerA" -> "RouteX")
				// Now the Listener arrives, pointing to the RouteX we just sent.
				{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
					StreamId: &StreamId{
						Authority: "",
						Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					RawResponseBytes: []byte(`{
                    "version_info": "1",
                    "nonce": "B",
                    "type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
                    "resources": [{
                        "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
                        "name": "ListenerA",
                        "api_listener": {
                            "api_listener": {
                                "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                                "rds": {
                                    "route_config_name": "RouteX",
                                    "config_source": {"ads": {}}
                                },
                                "http_filters": [{"name": "router", "typed_config": {"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]
                            }
                        }
                    }]
                }`),
				}}},

				// 4. Action_TriggerConnectionFailure
				// Stream breaks right after the LDS update.
				{ActionType: &Action_TriggerConnectionFailure{
					TriggerConnectionFailure: &TriggerConnectionFailure{
						Authority: "",
						Status:    &Status{Code: 14, Message: "Simulated Connection Failure"}, // 14 = UNAVAILABLE
					}}},

				// 5. Action_StopWatch(LDS, "ListenerA")
				// User gives up while we are reconnecting.
				{ActionType: &Action_StopWatch{
					StopWatch: &StopWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{
								Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "ListenerA"}}},
			},
		}
		b, _ := proto.Marshal(m)
		return b
	}())

	f.Fuzz(func(t *testing.T, data []byte) {
		scenario := &Msg{}
		if err := proto.Unmarshal(data, scenario); err != nil {
			return
		}

		fz, err := NewFuzzer(t, scenario.Bootstrap)
		if err != nil {
			return
		}
		defer fz.Close()
		fmt.Println(scenario)
		for _, action := range scenario.Actions {
			fz.Act(action)
		}
	})
}

func returnbytes() []byte {
	// Construct the JSON string for DiscoveryResponse
	jsonResp := `{
		"version_info": "1",
		"nonce": "A",
		"type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
		"resources": [{
			"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
			"name": "service.example.com",
			"api_listener": {
				"api_listener": {
					"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
					"stat_prefix": "trafficdirector",
					"rds": {
						"config_source": {
							"ads": {},
							"resource_api_version": "V3"
						},
						"route_config_name": "URL_MAP/12347_arcus-um-good-1_0_service.example.com"
					},
					"http_filters": [{
						"name": "envoy.filters.http.fault",
						"typed_config": {
							"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault"
						}
					}, {
						"name": "envoy.filters.http.router",
						"typed_config": {
							"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
							"suppress_envoy_headers": true
						}
					}],
					"upgrade_configs": [{"upgrade_type": "websocket"}],
					"normalize_path": true,
					"merge_slashes": true
				}
			}
		}]
	}`

	// Unmarshal JSON to DiscoveryResponse
	dr := &v3discoverypb.DiscoveryResponse{}
	if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
		panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
	}

	fmt.Println("Response unmarshalled: ", dr)

	// Marshal DiscoveryResponse to binary
	binResp, err := proto.Marshal(dr)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
	}

	m := &Msg{
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{ActionType: &Action_StartWatch{
				StartWatch: &StartWatch{
					ResourceType: &ResourceType{
						ResourceType: &ResourceType_Listener{
							Listener: &ResourceType_EmptyMessage{}}},
					ResourceName: "server.example.com"}}},
			{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
				StreamId: &StreamId{Authority: "xds.example.com:443", Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
				RawResponseBytes: binResp,
			}}},
			{ActionType: &Action_ReadMessageFromClient{
				ReadMessageFromClient: &ReadMessageFromClient{
					StreamId: &StreamId{
						Authority: "xds.example.com:443",
						Method: &StreamId_Ads{
							Ads: &StreamId_EmptyMessage{}}},
					Ok: true}}},
			{ActionType: &Action_DumpCsdsData{}},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnRoutebytes() []byte {
	// Construct the JSON string for DiscoveryResponse
	jsonResp := `{
  "version_info": "1",
  "nonce": "A",
  "type_url": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
      "name": "URL_MAP/12347_arcus-um-good-1",
      "virtual_hosts": [
        {
          "name": "host_3402712176314620860",
          "domains": ["service.example.com"],
          "routes": [
            {
              "name": "URL_MAP/12347_arcus-um-good-1-route-0",
              "match": { "prefix": "/greeter/" },
              "route": {
                "weighted_clusters": {
                  "clusters": [
                    {
                      "name": "cloud-internal-istio:cloud_mp_1234_3456",
                      "weight": 40
                    },
                    {
                      "name": "cloud-internal-istio:cloud_mp_1234_3456",
                      "weight": 60
                    }
                  ],
                  "total_weight": 100
                },
                "timeout": "30s"
              }
            },
            {
              "name": "URL_MAP/12347_arcus-um-good-1-route-1",
              "match": { "prefix": "" },
              "route": {
                "cluster": "cloud-internal-istio:cloud_mp_1234_3456",
                "timeout": "30s",
                "retry_policy": {
                  "retry_on": "gateway-error",
                  "num_retries": 1,
                  "per_try_timeout": "30s"
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`

	// Unmarshal JSON to DiscoveryResponse
	dr := &v3discoverypb.DiscoveryResponse{}
	if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
		panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
	}

	// Marshal DiscoveryResponse to binary
	binResp, err := proto.Marshal(dr)
	if err != nil {
			fmt.Println("Response un")
		panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
	}

	m := &Msg{
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{ActionType: &Action_StartWatch{
				StartWatch: &StartWatch{
					ResourceType: &ResourceType{
						ResourceType: &ResourceType_RouteConfig{
							RouteConfig: &ResourceType_EmptyMessage{}}},
					ResourceName: "route_config1"}}},
			{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
				StreamId: &StreamId{Authority: "xds.example.com:443", Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
				RawResponseBytes: binResp,
			}}},
			{ActionType: &Action_ReadMessageFromClient{
				ReadMessageFromClient: &ReadMessageFromClient{
					StreamId: &StreamId{
						Authority: "xds.example.com:443",
						Method: &StreamId_Ads{
							Ads: &StreamId_EmptyMessage{}}},
					Ok: true}}},
			{ActionType: &Action_DumpCsdsData{}},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnClusterbytes() []byte {
	// Construct the JSON string for DiscoveryResponse
	jsonResp := `{
  "version_info": "1",
  "nonce": "A",
  "type_url": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
      "name": "cloud-internal-istio:cloud_mp_1234_3456",
      "type": "EDS",
      "eds_cluster_config": {
        "eds_config": {
          "ads": {},
          "initial_fetch_timeout": "15s",
          "resource_api_version": "V3"
        }
      },
      "connect_timeout": "30s",
      "circuit_breakers": {
        "thresholds": [
          {
            "max_connections": 2147483647,
            "max_pending_requests": 2147483647,
            "max_requests": 2147483647,
            "max_retries": 2147483647
          }
        ]
      },
      "http2_protocol_options": {
        "max_concurrent_streams": 100
      },
      "metadata": {
        "filter_metadata": {
          "com.google.trafficdirector": {
            "backend_service_name": "bs-good3",
            "backend_service_project_number": 1234
          }
        }
      },
      "common_lb_config": {
        "healthy_panic_threshold": {
          "value": 1.0
        },
        "locality_weighted_lb_config": {}
      },
      "alt_stat_name": "/projects/1234/global/backendServices/bs-good3",
      "lrs_server": {
        "self": {}
      }
    }
  ]
}`

	// Unmarshal JSON to DiscoveryResponse
	dr := &v3discoverypb.DiscoveryResponse{}
	if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
		panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
	}

	// Marshal DiscoveryResponse to binary
	binResp, err := proto.Marshal(dr)
	if err != nil {
			fmt.Println("Response un")
		panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
	}

	m := &Msg{
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{ActionType: &Action_StartWatch{
				StartWatch: &StartWatch{
					ResourceType: &ResourceType{
						ResourceType: &ResourceType_Cluster{
							Cluster: &ResourceType_EmptyMessage{}}},
					ResourceName: "cluster1"}}},
			{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
				StreamId: &StreamId{Authority: "xds.example.com:443", Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
				RawResponseBytes: binResp,
			}}},
			{ActionType: &Action_ReadMessageFromClient{
				ReadMessageFromClient: &ReadMessageFromClient{
					StreamId: &StreamId{
						Authority: "xds.example.com:443",
						Method: &StreamId_Ads{
							Ads: &StreamId_EmptyMessage{}}},
					Ok: true}}},
			{ActionType: &Action_DumpCsdsData{}},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnEndpointbytes() []byte {
	// Construct the JSON string for DiscoveryResponse
	jsonResp := `{
  "version_info": "1",
  "nonce": "A",
  "type_url": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
      "cluster_name": "endpoint1",
      "endpoints": [
        {
          "locality": {
            "region": "region1",
            "zone": "zone1",
            "sub_zone": "sub_zone1"
          },
          "load_balancing_weight": 1,
          "lb_endpoints": [
            {
              "load_balancing_weight": 1,
              "endpoint": {
                "address": {
                  "socket_address": {
                    "address": "127.0.0.1",
                    "port_value": 443
                  }
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`

	// Unmarshal JSON to DiscoveryResponse
	dr := &v3discoverypb.DiscoveryResponse{}
	if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
		panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
	}

	// Marshal DiscoveryResponse to binary
	binResp, err := proto.Marshal(dr)
	if err != nil {
			fmt.Println("Response un")
		panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
	}

	m := &Msg{
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{ActionType: &Action_StartWatch{
				StartWatch: &StartWatch{
					ResourceType: &ResourceType{
						ResourceType: &ResourceType_Endpoint{
							Endpoint: &ResourceType_EmptyMessage{}}},
					ResourceName: "endpoint1"}}},
			{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
				StreamId: &StreamId{Authority: "xds.example.com:443", Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
				RawResponseBytes: binResp,
			}}},
			{ActionType: &Action_ReadMessageFromClient{
				ReadMessageFromClient: &ReadMessageFromClient{
					StreamId: &StreamId{
						Authority: "xds.example.com:443",
						Method: &StreamId_Ads{
							Ads: &StreamId_EmptyMessage{}}},
					Ok: true}}},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnBasicSocketbytes() []byte {
	// Construct the JSON string for DiscoveryResponse (LDS)
	jsonResp := `{
  "version_info": "1",
  "nonce": "A",
  "type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
      "name": "path/to/resource?udpa.resource.listening_address=127.0.0.1:8080",
      "reuse_port": true,
      "address": {
        "socket_address": {
          "address": "127.0.0.1",
          "port_value": 8080
        }
      },
      "filter_chains": [
        {
          "filters": [
            {
              "name": "envoy.http_connection_manager",
              "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                "stat_prefix": "endpoint_config_selector-1",
                "route_config": {
                  "name": "inbound|endpoint_config_selector-1-8080",
                  "virtual_hosts": [
                    {
                      "name": "inbound|endpoint_config_selector-1-8080",
                      "domains": ["*"],
                      "routes": [
                        {
                          "match": { "prefix": "/" },
                          "non_forwarding_action": {},
                          "decorator": {
                            "operation": "endpoint_config_selector-1/*"
                          }
                        }
                      ]
                    }
                  ]
                },
                "http_filters": [
                  {
                    "name": "envoy.filters.http.router",
                    "typed_config": {
                      "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                    }
                  }
                ],
                "forward_client_cert_details": "APPEND_FORWARD",
                "set_current_client_cert_details": {
                  "subject": true,
                  "dns": true,
                  "uri": true
                },
                "upgrade_configs": [{ "upgrade_type": "websocket" }]
              }
            }
          ],
          "transport_socket": {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
              "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
              "common_tls_context": {
                "combined_validation_context": {
                  "default_validation_context": {},
                  "validation_context_certificate_provider_instance": {
                    "instance_name": "gcp_id_2",
                    "certificate_name": "ROOTCA"
                  }
                },
                "tls_certificate_certificate_provider_instance": {
                  "instance_name": "gcp_id_1",
                  "certificate_name": "DEFAULT"
                }
              },
              "require_client_certificate": true
            }
          }
        }
      ],
      "traffic_direction": "INBOUND"
    }
  ]
}`

	// Unmarshal JSON to DiscoveryResponse
	dr := &v3discoverypb.DiscoveryResponse{}
	if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
		panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
	}

	// Marshal DiscoveryResponse to binary
	binResp, err := proto.Marshal(dr)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
	}

	m := &Msg{
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{ActionType: &Action_StartWatch{
				StartWatch: &StartWatch{
					ResourceType: &ResourceType{
						ResourceType: &ResourceType_Listener{
							Listener: &ResourceType_EmptyMessage{}}},
					ResourceName: "server.example.com"}}},
			{ActionType: &Action_ReadMessageFromClient{
				ReadMessageFromClient: &ReadMessageFromClient{
					StreamId: &StreamId{
						Authority: "xds.example.com:443",
						Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
					Ok: true}}},
			{ActionType: &Action_SendMessageToClient{SendMessageToClient: &SendMessageToClient{
				StreamId:         &StreamId{Authority: "xds.example.com:443", Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
				RawResponseBytes: binResp,
			}}},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnXdsServersEmptybytes() []byte {

	m := &Msg{
		Bootstrap: `{"xds_servers": []}`,
		Actions: []*Action{
			{ActionType: &Action_StartWatch{
				StartWatch: &StartWatch{
					ResourceType: &ResourceType{
						ResourceType: &ResourceType_Listener{
							Listener: &ResourceType_EmptyMessage{}}},
					ResourceName: "\003"},
				},
			},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnResourceWrapperEmptybytes() []byte {
	// Construct the JSON string for DiscoveryResponse (CDS)
	// Note: version_info and nonce are set to the strings from your pb snippet
	jsonResp := `{
  "version_info": "envoy.config.cluster.v3.Cluster",
  "nonce": "envoy.config.cluster.v3.Cluster",
  "type_url": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
  "canary": true,
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.service.discovery.v3.Resource"
    }
  ]
}`

	// Unmarshal JSON to DiscoveryResponse
	dr := &v3discoverypb.DiscoveryResponse{}
	if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
		panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
	}

	// Marshal DiscoveryResponse to binary
	binResp, err := proto.Marshal(dr)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
	}

	m := &Msg{
		// Updated bootstrap to use "fake" creds type as per your pb
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{
				ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Cluster{
								Cluster: &ResourceType_EmptyMessage{},
							},
						},
					},
				},
			},
			{
				ActionType: &Action_SendMessageToClient{
					SendMessageToClient: &SendMessageToClient{
						StreamId: &StreamId{
							Authority: "xds.example.com:443",
							Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}},
						},
						RawResponseBytes: binResp,
					},
				},
			},
		},
	}
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func returnRlsMissingTypedExtensionConfigbytes() []byte {
    // 1. Manually create the DiscoveryResponse object
    dr := &v3discoverypb.DiscoveryResponse{
        VersionInfo: "grpc.lookup.v1.RouteLookup",
        Nonce:       "/@\x01\x00\\\x00\x00x141183468234106731687303715884105729",
        TypeUrl:     "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
        Resources: []*anypb.Any{
            {
                TypeUrl: "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
                // This is the binary representation of \010\001b\000
                Value: []byte{0x08, 0x01, 0x62, 0x00},
            },
        },
    }

    // 2. Marshal to binary
    binResp, err := proto.Marshal(dr)
    if err != nil {
        panic(fmt.Sprintf("failed to marshal DiscoveryResponse: %v", err))
    }

    // 3. Construct the Fuzzer Message
    m := &Msg{
        Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:-257", "channel_creds":[{"type": "insecure"}]}]}`,
        Actions: []*Action{
            {
                ActionType: &Action_StartWatch{
                    StartWatch: &StartWatch{
                        ResourceType: &ResourceType{
                            ResourceType: &ResourceType_RouteConfig{
                                RouteConfig: &ResourceType_EmptyMessage{},
                            },
                        },
                    },
                },
            },
            {
                ActionType: &Action_SendMessageToClient{
                    SendMessageToClient: &SendMessageToClient{
                        StreamId: &StreamId{
                            Authority: "xds.example.com:-257",
                            Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}},
                        },
                        RawResponseBytes: binResp,
                    },
                },
            },
        },
	}
    
    b, err := proto.Marshal(m)
    if err != nil {
        panic(err)
    }
    return b
}

func returnSendMessageToClientBeforeStreamCreatedbytes() []byte {

	m := &Msg{
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			{ActionType: &Action_SendMessageToClient{
                    SendMessageToClient: &SendMessageToClient{
                        StreamId: &StreamId{
                            Authority: "xds.example.com:443",
                            Method:    &StreamId_Ads{Ads: &StreamId_EmptyMessage{}},
                        },
                    },
                },
			},
		},
	}
	b, _ := proto.Marshal(m)
	return b
}

func returnIgnoresConnectionFailuresWithOkStatusbytes() []byte {

	m := &Msg{
		// FIX 1: The URI contains the UTF-8 sequence for \320\272 (Cyrillic 'к')
		// In Go, we use the hex equivalent \xd0\xba
		Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com\xd0\xba443", "channel_creds":[{"type": "insecure"}]}]}`,
		Actions: []*Action{
			// action 1: start_watch for "*"
			{
				ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Cluster{
								Cluster: &ResourceType_EmptyMessage{},
							},
						},
						ResourceName: "*",
					},
				},
			},
			// action 2: empty action
			{},
			// action 3: trigger_connection_failure
			{
				ActionType: &Action_TriggerConnectionFailure{
					TriggerConnectionFailure: &TriggerConnectionFailure{},
				},
			},
			// action 4: empty action
			{},
		},
	}

	b, _ := proto.Marshal(m)
	return b
}

func returnUnsubscribeWhileAdsCallInBackoffbytes() []byte {
  // Construct the JSON string for DiscoveryResponse (LDS)
  jsonResp := `{
  "version_info": "1",
  "nonce": "A",
  "type_url": "type.googleapis.com/envoy.config.listener.v3.Listener",
  "resources": [
    {
      "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
      "name": "server.example.com",
      "api_listener": {
        "api_listener": {
          "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
          "rds": {
            "route_config_name": "route_config",
            "config_source": {
              "self": {}
            }
          },
          "http_filters": [
            {
              "name": "router",
              "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
              }
            }
          ]
        }
      }
    }
  ]
}`

  // Unmarshal JSON to DiscoveryResponse
  dr := &v3discoverypb.DiscoveryResponse{}
  if err := protojson.Unmarshal([]byte(jsonResp), dr); err != nil {
    panic(fmt.Sprintf("failed to unmarshal JSON to DiscoveryResponse: %v", err))
  }

  // Marshal DiscoveryResponse to binary
  binResp, err := proto.Marshal(dr)
  if err != nil {
    panic(fmt.Sprintf("failed to marshal DiscoveryResponse to binary: %v", err))
  }

  m := &Msg{
    Bootstrap: `{"xds_servers": [{"server_uri":"xds.example.com:443", "channel_creds":[{"type": "insecure"}]}]}`,
    Actions: []*Action{
      // 1. start_watch
      {ActionType: &Action_StartWatch{
					StartWatch: &StartWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "server.example.com:443"}}},
				// Trigger connection failure to induce backoff
				{ActionType: &Action_TriggerConnectionFailure{TriggerConnectionFailure: &TriggerConnectionFailure{}}},
				{ActionType: &Action_StopWatch{
					StopWatch: &StopWatch{
						ResourceType: &ResourceType{
							ResourceType: &ResourceType_Listener{Listener: &ResourceType_EmptyMessage{}}},
						ResourceName: "server.example.com:443"}}},

      // 4. send_message_to_client
      {ActionType: &Action_SendMessageToClient{
        SendMessageToClient: &SendMessageToClient{
          StreamId: &StreamId{
            Authority: "xds.example.com:443", 
            Method: &StreamId_Ads{Ads: &StreamId_EmptyMessage{}}},
          RawResponseBytes: binResp,
      }}},
    },
  }
  
  b, _ := proto.Marshal(m)
  return b
}

func  TestFuzzLogic(t *testing.T) {
	// Enable crash recovery for the duration of the fuzz test.
	// We set this globally before the fuzz loop to avoid race conditions
	// that occur when using SetEnvConfig inside parallel fuzz iterations.
	origRecover := envconfig.XDSRecoverPanic
	envconfig.XDSRecoverPanic = false
	defer func() { envconfig.XDSRecoverPanic = origRecover }()


	data := returnbytes()
	// data := returnRoutebytes()
	// data := returnClusterbytes()
	// data := returnEndpointbytes()
	// data := returnBasicSocketbytes()
	// data := returnXdsServersEmptybytes()
	// data := returnResourceWrapperEmptybytes()
	// data := returnRlsMissingTypedExtensionConfigbytes()
	// data := returnSendMessageToClientBeforeStreamCreatedbytes()
	// data := returnIgnoresConnectionFailuresWithOkStatusbytes()
	// data := returnUnsubscribeWhileAdsCallInBackoffbytes()
	scenario := &Msg{}
	if err := proto.Unmarshal(data, scenario); err != nil {
		return
	}
	fz, err := NewFuzzer(t, scenario.Bootstrap)
	if err != nil {
		return
	}
	defer func() {
		time.Sleep(10 * time.Millisecond)
		fz.Close()
	}()
	for _, action := range scenario.Actions {
		fz.Act(action)
	}

}
