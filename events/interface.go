package events

type GlooArgs struct {
	// address of the gloo gateway
	Addr string
	// optional tls config if user has custom tls settings
	TlsConfig
}

type TlsConfig struct {
	// paths to custom root certificate PEM
	CustomRootCAs []string

	ClientCertificates []ClientKeypair

	InsecureVerify bool
}

type ClientKeypair struct {
	// path to the public key PEM
	PublicKey string
	// path to the public key
	PrivateKey string
}

type Gloo interface {
	Emitter(sourceId string, contentType ...string) Emitter
}

type Emitter interface {
	Emit(topic string, data interface{}) error
}
