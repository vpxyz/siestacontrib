SiestaContrib: Middleware for VividCortex Siesta
=================

SiestaContrib contains some simple middleware for VividCortex Siesta. 

The middleware are:
+ CORS Filter
+ more to come....


CORS Filter Example
==================

CORS Filter handle both simple and preflight request.

First of all install SiestaContrib:

    go get -u github.com/vpxyz/siestacontrib

Now you can combine your handlers with the cors filter:


``` go
package main

import (
	"fmt"
	"github.com/VividCortex/siesta"
	"github.com/vpxyz/siestacontrib/cors"
	"log"
	"net/http"
	"os"
)


func main() {
	service := siesta.NewService("/")

	logger := log.New(os.Stdout, "CORS: ", log.LstdFlags)

    corsFilter := cors.New(
		"http://*.example.com ,http://*.edu", // origins 
        cors.DefaultAllowMethods + "," + http.MethodOptions + "," + http.MethodPut, // put here your allowed methods
		cors.DefaultAllowHeaders+",X-Custom-Header", // allowed headers
		3000,
		"X-Custom-Header", // exposer headers
		true, // yes, allow credentials
		logger, // optional, can be nil
	)

    // add the CORS middleware to the "pre" chain.
	service.AddPre(corsFilter.Filter)

	service.Route("GET", "/square", "Prints the square of a number.",
		func(w http.ResponseWriter, r *http.Request) {
			var params siesta.Params
			number := params.Int("number", 0, "A number to square")

			err := params.Parse(r.Form)
			if err != nil {
				log.Println("Error parsing parameters!", err)
				return
			}

			fmt.Fprintf(w, "%d * %d = %d.", *number, *number, (*number)*(*number))
		},
	)

	log.Println("Listening on :8080")
	panic(http.ListenAndServe(":8080", service))

}
```

Alternative, there is a default CORS Filter configuration that allow all origins and basic methd and header.

    corsFilter := cors.DefaultNew(logger)

*logger* is optional.


In order to check, try:

    curl -H "Origin:http://www.example.com" --verbose localhost:8080/square?number=10


preflight request:

    curl -H "Origin: http://www.example.com" \
      -H "Access-Control-Request-Method: POST" \
      -H "Access-Control-Request-Headers: X-Custom-Header" \
      -X OPTIONS --verbose \
      localhost:8080/square?number=10


