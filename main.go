package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	snmp "github.com/soniah/gosnmp"
	"gopkg.in/tylerb/graceful.v1"
	"gopkg.in/yaml.v2"
)

var (
	Version   string = "0.0.0"
	GitHash   string = "unknown"
	BuildTime string = "unknown"
)

// daemon's configuration
type Config struct {
	// HTTP listen on
	Http struct {
		// local address listen on, for example ":http"
		Address string `json:"address,omitempty" yaml:"address,omitempty"`

		// export custom HTML directory
		HtmlDir string `json:"html-dir,omitempty" yaml:"html-dir,omitempty"`

		// additional HTTP response headers
		Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	} `json:"http,omitempty" yaml:"http,omitempty"`

	// SNMP targets
	Snmp []SnmpTarget
}

// one SNMP target
type SnmpTarget struct {
	Name      string `json:"name" yaml:"name"`
	Target    string `json:"target,omitempty" yaml:"target,omitempty"`
	Port      int    `json:"port,omitempty" yaml:"port,omitempty"`
	Community string `json:"community,omitempty" yaml:"community,omitempty"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
	// TODO: allowed OID (read, write)
}

// LoadConfig loads configuration file
func LoadConfig(filename string) (*Config, error) {
	// read the whole configuration file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %s", err)
	}

	// try to parse it as YAML file
	cfg := &Config{}
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %s", err)
	}

	return cfg, nil // OK
}

// find SNMP target by name
func (cfg *Config) findSnmpTargetByName(name string) *SnmpTarget {
	for i := range cfg.Snmp {
		if cfg.Snmp[i].Name == name {
			return &cfg.Snmp[i]
		}
	}

	return nil // not found
}

// daemon's entry point
func main() {
	var confPath string
	var version bool
	flag.StringVar(&confPath, "config", "snmp.conf", "Configuration file")
	flag.BoolVar(&version, "version", false, "Show version info")
	flag.Parse()

	// print version and exit
	if version {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("GitHash: %s\n", GitHash)
		fmt.Printf("BuildTime: %s\n", BuildTime)
		return
	}

	log.Printf("loading configuration from %s", confPath)
	cfg, err := LoadConfig(confPath)
	if err != nil {
		log.Fatalf("failed to load configuration: %s", err)
	}

	// create service instance
	service := NewService(cfg)

	// start HTTP server
	var httpServer *graceful.Server
	if cfg := cfg.Http; cfg.Address != "" {
		httpServer = &graceful.Server{
			Server: &http.Server{
				Handler: service,
				Addr:    cfg.Address,
			}}

		go func() {
			defer log.Printf("HTTP server has stopped")
			log.Printf("starting HTTP server at %s", cfg.Address)
			if err := httpServer.ListenAndServe(); err != nil {
				log.Fatalf("failed to start HTTP server: %s", err)
			}
		}()
	}

	// catch common signals
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, os.Kill)

	log.Printf("to stop service send SIGTERM (or press Ctrl+C)...")

	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("FATAL: %v", r)
			}
		}()

		//service.Init()
		for {
			select {
			case sig := <-sigCh: // wait signal
				log.Printf("%s signal received", sig)
				return

			case <-time.After(1 * time.Second):
				//service.Loop()
			}
		}
	}()

	// stop all services
	//service.Stop()

	// wait all servers
	if httpServer != nil {
		httpServer.Stop(1 * time.Second)
		log.Printf("wait HTTP server...")
		<-httpServer.StopChan()
	}

	log.Printf("done")
}

// HTTP error contains status code and corresponding error message.
type HttpError struct {
	Code    int    // HTTP status code
	Message string // message
}

// get error's message
func (e *HttpError) Error() string {
	return e.Message
}

// create new HTTP error
func NewHttpError(code int, msg string) *HttpError {
	return &HttpError{
		Code:    code,
		Message: msg,
	}
}

// create new HTTP error
func NewHttpErrorf(code int, msg string, args ...interface{}) *HttpError {
	return NewHttpError(code, fmt.Sprintf(msg, args...))
}

// check for panics
func checkPanic(w http.ResponseWriter) {
	if r := recover(); r != nil {
		if err, ok := r.(*HttpError); ok {
			// special case for HttpErrors...
			log.Printf("  FAILED: %d %s", err.Code, err.Message)
			err := writeJson0(w, err.Code,
				map[string]interface{}{
					"code":    err.Code,
					"message": err.Message,
				})
			if err != nil {
				log.Printf("  FAILED to write error response: %s", err)
			}
		} else {
			log.Printf("  FAILED: %s", r)
			http.Error(w, fmt.Sprintf("%s", r),
				http.StatusInternalServerError)
		}
	}
}

// check allowed methods
func checkMethod(r *http.Request, methods ...string) {
	for _, m := range methods {
		if r.Method == m {
			return // OK
		}
	}

	// method not allowed
	if len(methods) == 1 {
		panic(NewHttpErrorf(http.StatusMethodNotAllowed,
			"only %s method is allowed", methods[0]))
	} else {
		panic(NewHttpErrorf(http.StatusMethodNotAllowed,
			"only %s methods are allowed", methods))
	}
}

// custom service
type Service struct {
	http.ServeMux
	cfg *Config
}

// create new service
func NewService(cfg *Config) *Service {
	s := &Service{cfg: cfg}

	// install all handlers
	s.HandleFunc("/api/version", s.restGetVersion)
	s.HandleFunc("/api/snmp", s.restSnmp)

	return s // OK
}

// add common HTTP headers to the response
func (s *Service) applyHeaders(w http.ResponseWriter) {
	// add headers
	for h, v := range s.cfg.Http.Headers {
		w.Header().Add(h, v)
	}
}

// GET /version
func (s *Service) restGetVersion(w http.ResponseWriter, r *http.Request) {
	defer checkPanic(w)
	checkMethod(r, "GET")
	s.applyHeaders(w)

	writeJson(w, http.StatusOK,
		map[string]interface{}{
			"Version":   Version,
			"GitHash":   GitHash,
			"BuildTime": BuildTime,
		})
}

// GET or PUT /snmp
func (s *Service) restSnmp(w http.ResponseWriter, r *http.Request) {
	defer checkPanic(w)
	checkMethod(r, "GET", "PUT")
	s.applyHeaders(w)

	switch r.Method {
	case "GET":
		s._restGetSnmp(w, r)
	case "PUT":
		s._restPutSnmp(w, r)
	}

}

// GET /snmp
func (s *Service) _restGetSnmp(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var res []interface{}
	for _, name := range q["name"] {
		if target := s.cfg.findSnmpTargetByName(name); target != nil {
			// prepare worker
			w := &snmp.GoSNMP{
				Target:    target.Target,
				Port:      uint16(target.Port),
				Community: target.Community,
				Version:   mustParseSnmpVersion(target.Version),
				Timeout:   20 * time.Second,
				Retries:   6,
			}

			// try to connect
			if err := w.Connect(); err != nil {
				panic(NewHttpErrorf(http.StatusInternalServerError,
					"failed to connect SNMP agent %s:%d: %s",
					target.Target, target.Port, err))
			}
			defer w.Conn.Close()

			// GET requested OIDs
			result, err := w.Get(q["oid"]) // up to snmp.MAX_OIDS
			if err != nil {
				panic(NewHttpErrorf(http.StatusInternalServerError,
					"failed to do SNMP/GET to %s:%d: %s",
					target.Target, target.Port, err))
			}

			// report all variables
			var values []interface{}
			for _, v := range result.Variables {
				values = append(values,
					map[string]interface{}{
						"oid":   v.Name,
						"type":  snmpTypeAsString(v.Type),
						"value": snmpGoValue(v.Type, v.Value),
					})
			}

			res = append(res,
				map[string]interface{}{
					"name":   name,
					"values": values,
				})
		} else {
			panic(NewHttpErrorf(http.StatusBadRequest,
				"no configured %s SNMP target found", name))
		}
	}

	writeJson(w, http.StatusOK, res)
}

// PUT /snmp
func (s *Service) _restPutSnmp(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// TODO: get JSON body and convert it snmp.PDU
	panic(NewHttpError(http.StatusNotImplemented,
		"PUT not implemented yet"))

	var res []interface{}
	for _, name := range q["name"] {
		if target := s.cfg.findSnmpTargetByName(name); target != nil {
			// prepare worker
			w := &snmp.GoSNMP{
				Target:    target.Target,
				Port:      uint16(target.Port),
				Community: target.Community,
				Version:   mustParseSnmpVersion(target.Version),
				Timeout:   20 * time.Second,
				Retries:   6,
			}

			// try to connect
			if err := w.Connect(); err != nil {
				panic(NewHttpErrorf(http.StatusInternalServerError,
					"failed to connect SNMP agent %s:%d: %s",
					target.Target, target.Port, err))
			}
			defer w.Conn.Close()

			// GET requested OIDs
			/*
				result, err := w.Set(q["oid"]) // up to snmp.MAX_OIDS
				if err != nil {
					panic(NewHttpErrorf(http.StatusInternalServerError,
						"failed to do SNMP/GET to %s:%d: %s",
						target.Target, target.Port, err))
				}

				// report all variables
				var values []interface{}
				for _, v := range result.Variables {
					values = append(values,
						map[string]interface{}{
							"oid":   v.Name,
							"type":  snmpTypeAsString(v.Type),
							"value": snmpGoValue(v.Type, v.Value),
						})
				}

				res = append(res,
					map[string]interface{}{
						"name":   name,
						"values": values,
					})
			*/
		} else {
			panic(NewHttpErrorf(http.StatusBadRequest,
				"no configured %s SNMP target found", name))
		}
	}

	writeJson(w, http.StatusOK, res)
}

// parse SNMP version string
func mustParseSnmpVersion(version string) snmp.SnmpVersion {
	switch version {
	case "1":
		return snmp.Version1
	case "2c", "": // by default use "2c"
		return snmp.Version2c
	case "3":
		return snmp.Version3
	}

	panic(NewHttpErrorf(http.StatusBadRequest,
		"%q unknown SNMP version", version))
}

// SNMP type to string
func snmpTypeAsString(t snmp.Asn1BER) string {
	switch t {
	case snmp.UnknownType:
		return "unknown"
	case snmp.Boolean:
		return "bool"
	case snmp.Integer:
		return "int"
	case snmp.BitString:
		return "bit-string"
	case snmp.OctetString:
		return "octet-string"
	case snmp.Null:
		return "null"
	case snmp.ObjectIdentifier:
		return "oid"
	case snmp.ObjectDescription:
		return "desc"
	case snmp.IPAddress:
		return "ip"
	case snmp.Counter32:
		return "counter32"
	case snmp.Gauge32:
		return "gauge32"
	case snmp.TimeTicks:
		return "time-ticks"
	case snmp.Opaque:
		return "opaque"
	case snmp.NsapAddress:
		return "nsap"
	case snmp.Counter64:
		return "counter64"
	case snmp.Uinteger32:
		return "uint32"
	case snmp.NoSuchObject:
		return "no obj"
	case snmp.NoSuchInstance:
		return "no inst"
	case snmp.EndOfMibView:
		return "end of MIB"
	}

	return fmt.Sprintf("#%02x", t)
}

// get appropariate Go-typed value
func snmpGoValue(t snmp.Asn1BER, v interface{}) interface{} {
	switch t {
	case snmp.OctetString:
		return string(v.([]byte))

	// TODO: more types here!!!

	default:
		return snmp.ToBigInt(v)
	}
}

// write JSON data (without panics)
func writeJson0(w http.ResponseWriter, code int, data interface{}) error {
	// prepare output
	buf, err := json.Marshal(data)
	if err != nil {
		return NewHttpErrorf(http.StatusInternalServerError,
			"failed to marshal JSON response: %s", err)
	}

	// send it to a client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err = w.Write(buf)
	if err != nil {
		return fmt.Errorf("failed to write response: %s", err)
	}

	return nil // OK
}

// write JSON data
func writeJson(w http.ResponseWriter, code int, data interface{}) {
	if err := writeJson0(w, code, data); err != nil {
		panic(err)
	}
}

// parse JSON data
func readJson(r *http.Request, data interface{}) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(NewHttpErrorf(http.StatusBadRequest,
			"failed to read request body: %s", err))
	}

	// parse input
	err = json.Unmarshal(buf, data)
	if err != nil {
		panic(NewHttpErrorf(http.StatusBadRequest,
			"failed to parse request JSON body: %s", err))
	}
}
