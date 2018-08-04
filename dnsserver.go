package dnsserver

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Encapsulates the data segment of a SRV record. Priority and Weight are
// always 0 in our SRV records.
type SRVRecord struct {
	Port uint16
	Host string
}

func (s SRVRecord) Equal(s2 SRVRecord) bool {
	return s.Port == s2.Port && s.Host == s2.Host
}

// Struct which describes the DNS server.
type DNSServer struct {
	Domain          string                 // using the constructor, this will always end in a '.', making it a FQDN.
	aRecords        map[string][]net.IP    // FQDN -> IP
	srvRecords      map[string][]SRVRecord // service (e.g., _test._tcp) -> SRV
	cnameRecords    map[string]string
	cnameMutex      sync.RWMutex // mutex for CNAME record operations
	aMutex          sync.RWMutex // mutex for A record operations
	srvMutex        sync.RWMutex // mutex for SRV record operations
	randomize       bool         //randomize IPs if A record has multiple ip addresses
	maxIPsPerRecord int          //return only this amount of ip addresses for A records
}

// Create a new DNS server. Domain is an unqualified domain that will be used
// as the TLD.
func NewDNSServer(domain string, randomize bool, maxIPsPerRecord int) *DNSServer {
	return &DNSServer{
		Domain:          domain + ".",
		aRecords:        map[string][]net.IP{},
		cnameRecords:    map[string]string{},
		srvRecords:      map[string][]SRVRecord{},
		cnameMutex:      sync.RWMutex{},
		aMutex:          sync.RWMutex{},
		srvMutex:        sync.RWMutex{},
		randomize:       randomize,
		maxIPsPerRecord: maxIPsPerRecord,
	}
}

// Listen for DNS requests. listenSpec is a dotted-quad + port, e.g.,
// 127.0.0.1:53. This function blocks and only returns when the DNS service is
// no longer functioning.
func (ds *DNSServer) Listen(listenSpec string) error {
	return dns.ListenAndServe(listenSpec, "udp", ds)
}

// Convenience function to ensure the fqdn is well-formed, and keeps the
// set/delete interface easy.
func (ds *DNSServer) qualifyHost(host string) string {
	if host == "" {
		return ds.Domain
	}
	return host + "." + ds.Domain
}

// Convenience function to ensure that SRV names are well-formed.
func (ds *DNSServer) qualifySrv(service, protocol string) string {
	return fmt.Sprintf("_%s._%s.%s", service, protocol, ds.Domain)
}

// rewrites supplied host entries to use the domain this dns server manages
func (ds *DNSServer) qualifySrvHosts(srvs []SRVRecord) []SRVRecord {
	newsrvs := []SRVRecord{}

	for _, srv := range srvs {
		newsrvs = append(newsrvs, SRVRecord{
			Host: ds.qualifyHost(srv.Host),
			Port: srv.Port,
		})
	}

	return newsrvs
}

// Sets a host to an IP. Note that this is not the FQDN, but a hostname.
func (ds *DNSServer) SetCNAME(host string, domain string) {
	ds.cnameMutex.Lock()
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	ds.cnameRecords[ds.qualifyHost(host)] = domain
	ds.cnameMutex.Unlock()
}

// Receives a FQDN; looks up and supplies the A records.
func (ds *DNSServer) GetCNAME(fqdn string) *dns.CNAME {
	ds.cnameMutex.RLock()
	defer ds.cnameMutex.RUnlock()
	val, ok := ds.cnameRecords[fqdn]
	if ok {
		return &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				// 0 TTL results in UB for DNS resolvers and generally causes problems.
				Ttl: 30,
			},
			Target: val,
		}

	}

	return nil
}

// Receives a FQDN; looks up and supplies the A records.
func (ds *DNSServer) GetA(fqdn string) []dns.RR {
	ds.aMutex.RLock()
	defer ds.aMutex.RUnlock()
	val, ok := ds.aRecords[fqdn]

	if !ok && strings.Count(fqdn, ".") > 2 {
		fqdn_no_sub := strings.SplitAfterN(fqdn, ".", 2)[1]
		val, ok = ds.aRecords["*."+fqdn_no_sub]
	}
	if ok {
		rr_records := []dns.RR{}
		for i := 0; i < len(val); i++ {
			rr_records = append(rr_records, &dns.A{
				Hdr: dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					// 0 TTL results in UB for DNS resolvers and generally causes problems.
					Ttl: 30,
				},
				A: val[i],
			})
		}
		return rr_records

	}

	return nil
}
func (ds *DNSServer) GetRandomizedA(fqdn string) []dns.RR {
	records := ds.GetA(fqdn)
	for i := len(records) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		records[i], records[j] = records[j], records[i]
	}
	return records
}

// Sets a host to an IP. Note that this is not the FQDN, but a hostname.
func (ds *DNSServer) SetA(host string, ip net.IP) {
	ds.aMutex.Lock()
	ds.aRecords[ds.qualifyHost(host)] = append(ds.aRecords[ds.qualifyHost(host)], ip)

	ds.aMutex.Unlock()
}

// Sets a host to an IP. Note that this is not the FQDN, but a hostname.
func (ds *DNSServer) SetMultipleA(host string, ips []net.IP) {
	ds.aMutex.Lock()
	ds.aRecords[ds.qualifyHost(host)] = ips

	ds.aMutex.Unlock()
}

// Deletes a host. Note that this is not the FQDN, but a hostname.
func (ds *DNSServer) DeleteA(host string, ip net.IP) {
	ds.aMutex.Lock()
	var key int
	for i := 0; i < len(ds.aRecords[ds.qualifyHost(host)]); i++ {
		if ds.aRecords[ds.qualifyHost(host)][i].Equal(ip) {
			key = i
		}
	}
	fmt.Println("will delete", ds.aRecords[ds.qualifyHost(host)][key])
	ds.aRecords[ds.qualifyHost(host)] = append(ds.aRecords[ds.qualifyHost(host)][:key], ds.aRecords[ds.qualifyHost(host)][key+1:]...)
	ds.aMutex.Unlock()
}

// Given a service spec, looks up and returns an array of *dns.SRV objects.
// These must be massaged into the []dns.RR after the fact.
func (ds *DNSServer) GetSRV(spec string) []*dns.SRV {
	ds.srvMutex.RLock()
	defer ds.srvMutex.RUnlock()

	srv, ok := ds.srvRecords[spec]

	if ok {
		records := []*dns.SRV{}
		for _, record := range srv {
			srvRecord := &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   spec,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					// 0 TTL results in UB for DNS resolvers and generally causes problems.
					Ttl: 1,
				},
				Priority: 0,
				Weight:   0,
				Port:     record.Port,
				Target:   record.Host,
			}

			records = append(records, srvRecord)
		}

		return records
	}

	return nil
}

// Sets a SRV with a service and protocol. See SRVRecord for more information
// on what that requires.
func (ds *DNSServer) SetSRV(service, protocol string, srvs []SRVRecord) {
	ds.srvMutex.Lock()
	ds.srvRecords[ds.qualifySrv(service, protocol)] = ds.qualifySrvHosts(srvs)
	ds.srvMutex.Unlock()
}

// Deletes a SRV record based on the service and protocol.
func (ds *DNSServer) DeleteSRV(service, protocol string) {
	ds.srvMutex.Lock()
	delete(ds.srvRecords, ds.qualifySrv(service, protocol))
	ds.srvMutex.Unlock()
}

// Main callback for miekg/dns. Collects information about the query,
// constructs a response, and returns it to the connector.
func (ds *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(r)

	answers := []dns.RR{}

	for _, question := range r.Question {
		// nil records == not found
		switch question.Qtype {
		case dns.TypeA:
			var a_records []dns.RR
			if ds.randomize {
				a_records = ds.GetRandomizedA(question.Name)
			} else {
				a_records = ds.GetA(question.Name)
			}
			if a_records != nil {
				if ds.maxIPsPerRecord != 0 && len(a_records) > ds.maxIPsPerRecord {
					a_records = a_records[0:ds.maxIPsPerRecord]

				} else {
					answers = append(answers, a_records...)
				}
			}
		case dns.TypeCNAME:
			cname_record := ds.GetCNAME(question.Name)
			if cname_record != nil {
				answers = append(answers, cname_record)
			}

		case dns.TypeSRV:
			srv := ds.GetSRV(question.Name)

			if srv != nil {
				for _, record := range srv {
					answers = append(answers, record)
				}
			}
		}
	}

	// If we have no answers, that means we found nothing or didn't get a query
	// we can reply to. Reply with no answers so we ensure the query moves on to
	// the next server.
	if len(answers) == 0 {
		m.SetRcode(r, dns.RcodeSuccess)
		w.WriteMsg(m)
		return
	}

	// Without these the glibc resolver gets very angry.
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Answer = answers
	w.WriteMsg(m)

}
