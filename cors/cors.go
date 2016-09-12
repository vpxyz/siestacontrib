package cors

import (
	"github.com/VividCortex/siesta"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	// DefaultAllowOrigins default origin allowed
	DefaultAllowOrigins = "*"

	// DefaultAllowMethods default method allowed
	DefaultAllowMethods = http.MethodGet + "," + http.MethodPost + "," + http.MethodHead + "," + http.MethodOptions

	// DefaultAllowOrigins default allowed origins
	DefaultAllowHeaders = "Origin,Accept,Content-Type,Accept-Language,Content-Language,Last-Event-ID" //default settings for cors

	AccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	AccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	AccessControlControlMaxAge    = "Access-Control-Max-Age"
	AccessControlAllowMethods     = "Access-Control-Allow-Methods"
	AccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	AccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	AccessControlRequestMethod    = "Access-Control-Request-Method"
	AccessControlRequestHeaders   = "Access-Control-Request-Headers"
	OriginHeader                  = "Origin"
	AcceptHeader                  = "Accept"
	ContentTypeHeader             = "Content-Type"
	AllowHeader                   = "Allow"
	VaryHeader                    = "Vary"
	OriginMatchAll                = "*"
)

// Cors cors filter for VividCortex siesta
type Cors struct {
	logger         *log.Logger
	allowedOrigins []*regexp.Regexp // store pre-compiled regular expression to match
	// the next two array are used to speedup match of headers and method
	allowedMethods   []string
	allowedHeaders   []string
	maxAge           string
	exposedHeaders   string
	exposeHeader     bool
	allowAllOrigins  bool
	allowCredentials bool
	// the next two variable store the original strings
	allowHeadersString   string
	allowedMethodsString string
}

// New initialize the cors filter with a comma separeted list of origins, methods and headers
func New(allowOrigins, allowMethods, allowHeaders string, maxAge int, exposedHeaders string, allowCredentials bool, logger *log.Logger) *Cors {
	cors := defaultNew()
	cors.logger = logger

	// default all origins
	if len(allowOrigins) > 0 && allowOrigins != "*" {
		origins := strings.Split(strings.ToLower(allowOrigins), ",")

		// now pre-copile pattern for regular expression match
		for _, o := range origins {
			p := regexp.QuoteMeta(strings.TrimSpace(o))
			p = strings.Replace(p, "\\*", ".*", -1)
			p = strings.Replace(p, "\\?", ".", -1)
			r := regexp.MustCompile(p) // compile pattern
			cors.allowedOrigins = append(cors.allowedOrigins, r)
		}

		cors.allowAllOrigins = false // default is all origins
	}

	if len(allowMethods) > 0 {
		// TODO: remove duplicated allowed  method
		cors.allowedMethods = strings.Split(strings.ToUpper(allowMethods), ",")
		cors.allowedMethodsString = allowMethods
	}

	if len(allowHeaders) > 0 {
		// TODO: remove duplicated allowed headers
		cors.allowedHeaders = strings.Split(strings.ToLower(allowHeaders), ",")
		cors.allowHeadersString = allowHeaders
	}

	cors.maxAge = strconv.Itoa(maxAge)

	if len(exposedHeaders) > 0 {
		cors.exposedHeaders = exposedHeaders
		cors.exposeHeader = true
	}

	cors.allowCredentials = allowCredentials

	cors.logWrap("cors filter configuration [%s]", cors)
	return cors
}

func defaultNew() *Cors {
	return &Cors{
		allowedMethods:  strings.Split(DefaultAllowMethods, ","),
		allowedHeaders:  strings.Split(strings.ToLower(DefaultAllowHeaders), ","),
		allowAllOrigins: true,
	}
}

// DefaultNew default filter
func DefaultNew(logger *log.Logger) *Cors {
	c := defaultNew()

	c.logger = logger
	c.logWrap("cors filter configuration [%s]", c)
	return c
}

// logWrap convenient log wrapper
func (cors *Cors) logWrap(format string, v ...interface{}) {
	if cors.logger != nil {
		cors.logger.Printf("[siestacontrib/cors] "+format, v...)
		return
	}

	log.Printf("[siestacontrib/cors] "+format, v...)
}

func (cors *Cors) String() string {
	var s string

	if cors.allowAllOrigins {
		s += "AllowedOrigins: *;"
	} else {
		s += "AllowedOrigins: "
		for _, r := range cors.allowedOrigins {
			s += r.String() + ","
		}
		s = s[:len(s)-1] + ";"
	}

	s += " AllowedHeaders: "
	for _, r := range cors.allowedHeaders {
		s += r + ","
	}
	s = s[:len(s)-1] + ";"

	s += " AllowedMethods: "
	for _, r := range cors.allowedMethods {
		s += r + ","
	}
	s = s[:len(s)-1] + ";"

	if cors.exposeHeader {
		s += " ExposeHeader: true;"
	} else {
		s += " ExposeHeader: false;"
	}

	s += " ExposedHeaders: " + cors.exposedHeaders + ";"

	s += " MaxAge:" + cors.maxAge

	return s
}

func (cors *Cors) isOriginAllowed(origin string) bool {

	if cors.allowAllOrigins {
		return true
	}

	origin = strings.ToLower(origin)

	for _, o := range cors.allowedOrigins {

		if o.MatchString(origin) {
			return true
		}
	}

	return false
}

// isMethodAllowed return true if the method is allowed
func (cors *Cors) isMethodAllowed(method string) bool {
	for _, m := range cors.allowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

// isHeaderAllowed return true if the header is allowed
func (cors *Cors) isHeaderAllowed(header string) bool {
	header = strings.ToLower(header)
	for _, h := range cors.allowedHeaders {
		if h == header {
			return true
		}
	}

	return false
}

func (cors *Cors) areReqHeadersAllowed(reqHeaders string) bool {
	if len(reqHeaders) == 0 {
		return true
	}

	requestHeaders := strings.Split(reqHeaders, ",")
	for _, v := range requestHeaders {
		// cors.logWrap("TRACE areReqHeadersAllowed: v = %s", v)
		canonicalHeader := http.CanonicalHeaderKey(strings.TrimSpace(v))
		// cors.logWrap("TRACE areReqHeadersAllowed: canonicalHeader = %s", canonicalHeader)
		if !cors.isHeaderAllowed(canonicalHeader) {
			// cors.logWrap("TRACE areReqHeadersAllowed: header not allowed return ''")
			return false
		}
	}

	return true

}

// preflightRequest handle preflight request
func (cors *Cors) preFlightRequest(c siesta.Context, w http.ResponseWriter, r *http.Request, quit func()) {
	w.Header().Add("Vary", AccessControlRequestMethod)
	w.Header().Add("Vary", AccessControlRequestHeaders)

	reqMethod := strings.ToUpper(r.Header.Get(AccessControlRequestMethod))

	if !cors.isMethodAllowed(reqMethod) {
		cors.logWrap("Filter: Preflight request not valid, requested method %s non allowed", reqMethod)
		w.WriteHeader(http.StatusMethodNotAllowed)

		// exit the chain here
		quit()
		return
	}

	reqHeaders := r.Header.Get(AccessControlRequestHeaders)

	if !cors.areReqHeadersAllowed(reqHeaders) {
		cors.logWrap("Filter: Preflight request not valid, request headers not allowed")
		w.WriteHeader(http.StatusForbidden)

		// exit the chain here
		quit()
		return
	}

	w.Header().Set(AccessControlAllowMethods, cors.allowedMethodsString)
	w.Header().Set(AccessControlAllowHeaders, cors.allowHeadersString)

	if cors.allowCredentials {
		w.Header().Set(AccessControlAllowCredentials, "true")
	}

	if cors.maxAge != "0" {
		w.Header().Set(AccessControlControlMaxAge, cors.maxAge)
	}

	// ok, now exit the chai with status HTTP 200
	w.WriteHeader(http.StatusOK)
	quit()
}

// Filter the cors filter
func (cors *Cors) Filter(c siesta.Context, w http.ResponseWriter, r *http.Request, quit func()) {

	// Allways add "Vary:Origin" header
	w.Header().Add("Vary", OriginHeader)

	origin := r.Header.Get(OriginHeader)

	// is not cors request, same origin request
	if origin == "" {
		c.Set("cors", false)
		return
	}

	if !cors.isMethodAllowed(r.Method) {
		cors.logWrap("Filter: Request method %s not allowed", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		quit()
		return
	}

	if !cors.isOriginAllowed(origin) {
		cors.logWrap("Filter: Origin %s not allowed", origin)
		w.WriteHeader(http.StatusForbidden)
		quit()
		return
	}

	// Ok, origin and method are allowed
	c.Set("cors", true)
	w.Header().Set(AccessControlAllowOrigin, origin)

	// handle a preflight request
	if r.Method == http.MethodOptions {
		c.Set("preflight", true)
		cors.preFlightRequest(c, w, r, quit)
		return
	}

	if cors.exposeHeader {
		w.Header().Set(AccessControlExposeHeaders, cors.exposedHeaders)
	}

	if cors.allowCredentials {
		w.Header().Set(AccessControlAllowCredentials, "true")
	}
}
