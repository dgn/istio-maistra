package federation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/host"
)

type FederationServer struct {
	Env        *model.Environment
	httpServer *http.Server
	Network    string
	clusterID  string
}

func NewFederationServer(env *model.Environment, clusterID, network string) *FederationServer {
	fed := &FederationServer{
		Env: env,
		httpServer: &http.Server{
			Addr:           ":8188",
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
		clusterID: clusterID,
		Network:   network,
	}
	mux := mux.NewRouter()
	mux.HandleFunc("/services/", fed.handleServiceList)
	mux.HandleFunc("/services/{name:[a-z1-9\\.\\-]+}", fed.handleService)
	fed.httpServer.Handler = mux
	return fed
}

func (s *FederationServer) getServiceMessage(svc *model.Service) *ServiceMessage {
	ret := &ServiceMessage{
		Name:         string(svc.Hostname),
		Generation:   int(svc.CreationTime.Unix()),
		ServicePorts: make([]*ServicePort, 0),
		Attributes:   make(map[string]string),
	}
	for _, port := range svc.Ports {
		ret.ServicePorts = append(ret.ServicePorts, &ServicePort{
			Name:     port.Name,
			Port:     port.Port,
			Protocol: string(port.Protocol),
		})
	}
	return ret
}

func (s *FederationServer) handleServiceList(response http.ResponseWriter, request *http.Request) {
	services, err := s.Env.Services()
	if err != nil {
		response.WriteHeader(500)
		return
	}
	ret := ServiceListMessage{
		NetworkGatewayEndpoints: []*ServiceEndpoint{},
	}
	for _, gateway := range s.Env.NetworkGateways()[s.Network] {
		ret.NetworkGatewayEndpoints = append(ret.NetworkGatewayEndpoints, &ServiceEndpoint{
			Port:     int(gateway.Port),
			Hostname: gateway.Addr,
		})
	}
	ret.Services = []*ServiceMessage{}
	for _, svc := range services {
		ret.Services = append(ret.Services, s.getServiceMessage(svc))
	}
	respBytes, err := json.Marshal(ret)
	if err != nil {
		response.WriteHeader(500)
		return
	}
	response.Write(respBytes)
}

func (s *FederationServer) handleService(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	svcName := params["name"]
	fmt.Printf("Looking up endpoints for service '%s'\n", svcName)
	svc, err := s.Env.GetService(host.Name(svcName))
	if svc == nil {
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}
		response.WriteHeader(404)
		return
	}
	ret := s.getServiceMessage(svc)
	respBytes, err := json.Marshal(ret)
	if err != nil {
		response.WriteHeader(500)
		return
	}
	response.Write(respBytes)
}

func (s *FederationServer) Run() {
	s.httpServer.ListenAndServe()
}
