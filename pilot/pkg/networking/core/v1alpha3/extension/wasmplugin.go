// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extension

import (
	udpa "github.com/cncf/udpa/go/udpa/type/v1"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	xdslistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm_filter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/conversion"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
	securitymodel "istio.io/istio/pilot/pkg/security/model"
	"istio.io/pkg/log"
)

const (
	defaultRuntime = "envoy.wasm.runtime.v8"

	IstioStatsPluginName      = "istio.stats"
	EnvoyHTTPRouterPluginName = "envoy.filters.http.router"

	WasmFilterTypeURL = "envoy.extensions.filters.http.wasm.v3.Wasm"
)

var (
	// CacheCluster is the Envoy cluster that is used to retrieve WASM filters from
	CacheCluster = ""
	// Runtime sets the WASM runtime to use for extensions
	Runtime = defaultRuntime

	defaultConfigSource = &envoy_config_core_v3.ConfigSource{
		ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
			Ads: &envoy_config_core_v3.AggregatedConfigSource{},
			// ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
			// 	ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
			// 	TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
			// 	GrpcServices: []*envoy_config_core_v3.GrpcService{
			// 		{
			// 			TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
			// 				EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{ClusterName: "xds-grpc"},
			// 			},
			// 		},
			// 	},
			// },
		},
		ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
	}
)

// AddWasmPluginsToListener adds WasmPlugins to listener filterChains
func AddWasmPluginsToListeners(
	listeners []*xdslistener.Listener,
	pluginsMap map[networking.EnvoyFilter_Patch_FilterClass][]*model.WasmPluginWrapper,
	proxy *model.Proxy,
	push *model.PushContext,
) []*xdslistener.Listener {
	ret := []*xdslistener.Listener{}
	for _, listener := range listeners {
		ret = append(ret, AddWasmPluginsToListener(listener, pluginsMap, proxy, push))
	}
	return ret
}

// AddWasmPluginsToListener adds WasmPlugins to listener filterChains
func AddWasmPluginsToListener(
	listener *xdslistener.Listener,
	pluginsMap map[networking.EnvoyFilter_Patch_FilterClass][]*model.WasmPluginWrapper,
	proxy *model.Proxy,
	push *model.PushContext,
) *xdslistener.Listener {
	if listener == nil {
		return nil
	}

	for fcIndex, fc := range listener.FilterChains {
		// copy extensions map
		extensions := make(map[networking.EnvoyFilter_Patch_FilterClass][]*model.WasmPluginWrapper)
		for phase, list := range pluginsMap {
			extensions[phase] = []*model.WasmPluginWrapper{}
			extensions[phase] = append(extensions[phase], list...)
		}
		hcm := &hcm_filter.HttpConnectionManager{}
		hcmIndex := -1
		for i, f := range fc.Filters {
			if f.Name == wellknown.HTTPConnectionManager && f.GetTypedConfig() != nil {
				if err := f.GetTypedConfig().UnmarshalTo(hcm); err == nil {
					hcmIndex = i
				}
				break
			}
		}
		if hcmIndex < 0 {
			continue
		}
		newHTTPFilters := make([]*hcm_filter.HttpFilter, 0)
		for _, httpFilter := range hcm.GetHttpFilters() {
			switch httpFilter.Name {
			case securitymodel.EnvoyJwtFilterName:
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHN)
				newHTTPFilters = append(newHTTPFilters, httpFilter)
			// case securitymodel.AuthnFilterName:
			// 	newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHN)
			// 	newHTTPFilters = append(newHTTPFilters, httpFilter)
			case authzmodel.RBACHTTPFilterName:
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHN)
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHZ)
				newHTTPFilters = append(newHTTPFilters, httpFilter)
			case IstioStatsPluginName:
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHN)
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHZ)
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_STATS)
				newHTTPFilters = append(newHTTPFilters, httpFilter)
			case EnvoyHTTPRouterPluginName:
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHN)
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_AUTHZ)
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_STATS)
				newHTTPFilters = popAppend(newHTTPFilters, extensions, networking.EnvoyFilter_Patch_UNSPECIFIED)
				newHTTPFilters = append(newHTTPFilters, httpFilter)
			default:
				newHTTPFilters = append(newHTTPFilters, httpFilter)
			}
		}
		hcm.HttpFilters = newHTTPFilters
		fc.Filters[hcmIndex] = &xdslistener.Filter{
			Name:       wellknown.HTTPConnectionManager,
			ConfigType: &xdslistener.Filter_TypedConfig{TypedConfig: util.MessageToAny(hcm)},
		}
		listener.FilterChains[fcIndex] = fc
	}
	return listener
}

func popAppend(list []*hcm_filter.HttpFilter,
	filterMap map[networking.EnvoyFilter_Patch_FilterClass][]*model.WasmPluginWrapper,
	phase networking.EnvoyFilter_Patch_FilterClass) []*hcm_filter.HttpFilter {
	for _, ext := range filterMap[phase] {
		if filter := toEnvoyHTTPFilter(ext); filter != nil {
			list = append(list, filter)
		}
	}
	filterMap[phase] = []*model.WasmPluginWrapper{}
	return list
}

func toEnvoyHTTPFilter(wasmPlugin *model.WasmPluginWrapper) *hcm_filter.HttpFilter {
	return &hcm_filter.HttpFilter{
		Name: wasmPlugin.Name,
		ConfigType: &hcm_filter.HttpFilter_ConfigDiscovery{
			ConfigDiscovery: &envoy_config_core_v3.ExtensionConfigSource{
				ConfigSource: defaultConfigSource,
				TypeUrls:     []string{WasmFilterTypeURL},
			},
		},
	}
}

// InsertedExtensionConfigurations returns extension configurations added via EnvoyFilter.
func InsertedExtensionConfigurations(
	wasmPlugins map[networking.EnvoyFilter_Patch_FilterClass][]*model.WasmPluginWrapper,
	names []string) []*envoy_config_core_v3.TypedExtensionConfig {
	result := make([]*envoy_config_core_v3.TypedExtensionConfig, 0)
	log.Infof("Want extensions: %v", names)
	if len(wasmPlugins) == 0 {
		return result
	}
	hasName := make(map[string]bool)
	for _, n := range names {
		hasName[n] = true
	}
	for _, list := range wasmPlugins {
		for _, p := range list {
			ws, _ := conversion.MessageToStruct(p.ExtensionConfiguration)
			ec := &envoy_config_core_v3.TypedExtensionConfig{
				Name: p.Name,
				TypedConfig: util.MessageToAny(&udpa.TypedStruct{
					TypeUrl: "type.googleapis.com/" + WasmFilterTypeURL,
					Value:   ws,
				}),
			}
			if _, ok := hasName[ec.GetName()]; ok {
				result = append(result, proto.Clone(ec).(*envoy_config_core_v3.TypedExtensionConfig))
			}
		}
	}
	return result
}
