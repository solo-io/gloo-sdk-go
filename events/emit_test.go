package events_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	. "github.com/solo-io/gloo-sdk-go/events"
)

var _ = Describe("Emit", func() {
	var server *ghttp.Server
	BeforeEach(func() {
		server = ghttp.NewTLSServer()
	})
	AfterEach(func() {
		server.Close()
	})
	Context("given an event emitted by the user", func() {
		It("sends the expected http request to the given url", func() {
			server.AppendHandlers(ghttp.VerifyRequest("POST", "/events"))
			data := struct {
				Foo string
				Bar int
			}{
				Foo: "foo",
				Bar: 1,
			}
			body, err := json.Marshal(data)
			Expect(err).NotTo(HaveOccurred())
			server.AppendHandlers(ghttp.VerifyBody(body))
			err = NewGloo(server.Addr(), &TlsConfig{InsecureVerify: true}).Emitter("test").Emit("topic", data)
			Expect(err).NotTo(HaveOccurred())
			Expect(server.ReceivedRequests()).To(HaveLen(1))
			req := server.ReceivedRequests()[0]

			Expect(req.Header.Get("Content-Type")).To(Equal("application/json"))
			Expect(req.Header.Get("X-Event-Content-Type")).To(Equal("application/json"))
			Expect(req.Header.Get("X-Cloud-Events-Version")).To(Equal("0.1"))
			Expect(req.Header.Get("X-Events-Id")).NotTo(BeEmpty())
			Expect(req.Header.Get("X-Event-Time")).NotTo(BeEmpty())
			Expect(req.Header.Get("X-Event-Type")).To(Equal("topic"))
			Expect(req.Header.Get("X-Source-Id")).To(Equal("test"))
		})
	})
})
