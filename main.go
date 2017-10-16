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

	// SNMP options
	Snmp struct {
		Target    string `json:"target,omitempty" yaml:"target,omitempty"`
		Port      int    `json:"port,omitempty" yaml:"port,omitempty"`
		Community string `json:"community,omitempty" yaml:"community,omitempty"`
	} `json:"snmp,omitempty" yaml:"snmp,omitempty"`
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

	service.startSNMP()

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

// run snmp service processing
func (s *Service) startSNMP() {
	// Build our own GoSNMP struct, rather than using g.Default.
	// Do verbose logging of packets.
	params := &snmp.GoSNMP{
		Target:    s.cfg.Snmp.Target,
		Port:      uint16(s.cfg.Snmp.Port),
		Community: s.cfg.Snmp.Community,
		Version:   snmp.Version2c,
		Timeout:   20 * time.Second,
		Retries:   5,
	}

	if err := params.Connect(); err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Conn.Close()

	oids := []string{"1.3.6.1.2.1.2.1", "1.3.6.1.2.1.2"}
	result, err := params.Get(oids) // Get() accepts up to g.MAX_OIDS
	if err != nil {
		log.Fatalf("Get() err: %v", err)
	}

	for i, variable := range result.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		// the Value of each variable returned by Get() implements
		// interface{}. You could do a type switch...
		switch variable.Type {
		case snmp.OctetString:
			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))

		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", snmp.ToBigInt(variable.Value))
		}
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
