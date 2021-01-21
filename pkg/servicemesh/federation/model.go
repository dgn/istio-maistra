package federation

type JoinMessage struct {
	TrustDomain              string `json:"trustDomain"`
	DiscoveryClientPrincipal string `json:"discoveryClientPrincipal"`
	DiscoveryEndpoint        string `json:"discoveryEndpoint"`
}

type ServiceListMessage struct {
	Generation              int                `json:"generation"`
	NetworkGatewayEndpoints []*ServiceEndpoint `json:"networkGatewayEndpoints"`
	Services                []*ServiceMessage  `json:"services"`
}

type ServiceMessage struct {
	Generation   int               `json:"generation"`
	Name         string            `json:"name"`
	ServicePorts []*ServicePort    `json:"servicePorts"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

type ServicePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type ServiceEndpoint struct {
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
}
