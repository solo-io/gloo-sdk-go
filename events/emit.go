package events

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/go-resty/resty"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
)

const (
	cloudEventsSpecVersion = "0.1"

	contentTypeJson = "application/json"
	eventPath       = "/events"
)

type gloo struct {
	addr      string
	tlsConfig *TlsConfig
}

func NewGloo(addr string, tlsConfig *TlsConfig) Gloo {
	return &gloo{addr: addr, tlsConfig: tlsConfig}
}

func (g *gloo) Emitter(sourceId string, contentType ...string) Emitter {
	ct := contentTypeJson
	if len(contentType) > 0 {
		ct = contentType[0]
	}
	return newEmitter(g.addr, g.tlsConfig, sourceId, ct)
}

type emitter struct {
	addr        string
	tlsConfig   *TlsConfig
	sourceId    string
	contentType string
}

func newEmitter(glooAddr string, tlsConfig *TlsConfig, sourceId, contentType string) Emitter {
	return &emitter{addr: glooAddr, tlsConfig: tlsConfig, sourceId: sourceId, contentType: contentType}
}

func (e *emitter) Emit(topic string, data interface{}) error {
	event := cloudEvent{
		Context: context{
			ContentType:        e.contentType,
			CloudEventsVersion: cloudEventsSpecVersion,
			EventId:            uuid.New(),
			EventTime:          time.Now(),
			EventType:          topic,
			Source: source{
				Id: e.sourceId,
			},
		},
		Data: data,
	}
	return doHttpRequest(e.addr, e.tlsConfig, event)
}

func doHttpRequest(addr string, tlsConfig *TlsConfig, event cloudEvent) error {
	// default to using json
	if event.Context.ContentType == "" {
		event.Context.ContentType = contentTypeJson
	}

	client := resty.New()
	if tlsConfig != nil {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: tlsConfig.InsecureVerify})
		for _, rootCA := range tlsConfig.CustomRootCAs {
			client.SetRootCertificate(rootCA)
		}
		for _, keypair := range tlsConfig.ClientCertificates {
			cert, err := tls.LoadX509KeyPair(keypair.PublicKey, keypair.PrivateKey)
			if err != nil {
				return errors.Wrap(err, "failed to load client certificate")
			}
			client.SetCertificates(cert)
		}
	}
	client.Header = constructHeaders(event.Context)
	resp, err := client.R().
		SetBody(event.Data).
		Post("https://" + addr + eventPath)
	if err != nil {
		return errors.Wrap(err, "performing http POST")
	}
	if resp.StatusCode()/100 != 2 {
		return errors.Errorf("request failed with status code %v", resp.StatusCode())
	}
	return nil
}

func constructHeaders(ctx context) http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", ctx.ContentType)
	headers.Set("X-Event-Content-Type", ctx.ContentType)
	headers.Set("X-Cloud-Events-Version", ctx.CloudEventsVersion)
	headers.Set("X-Events-Id", ctx.EventId)
	headers.Set("X-Event-Time", ctx.EventTime.Format(http.TimeFormat))
	headers.Set("X-Event-Type", ctx.EventType)
	headers.Set("X-Source-Id", ctx.Source.Id)
	return headers
}

// follows the cloudEvent v0.1 spec: https://github.com/cloudevents/spec/blob/master/spec.md
type cloudEvent struct {
	Context context
	Data    interface{}
}

type context struct {
	// currently used
	ContentType        string
	CloudEventsVersion string
	EventId            string
	EventTime          time.Time
	EventType          string
	Source             source

	// unused
	Namespace        string
	EventTypeVersion string
	SchemaUrl        string
	Extensions       map[string]interface{}
}

type source struct {
	Id string
	// unused
	Type string
}
