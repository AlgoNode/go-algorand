// Package data provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/algorand/oapi-codegen DO NOT EDIT.
package data

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	. "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/oapi-codegen/pkg/runtime"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Removes minimum sync round restriction from the ledger.
	// (DELETE /v2/ledger/sync)
	UnsetSyncRound(ctx echo.Context) error
	// Returns the minimum sync round the ledger is keeping in cache.
	// (GET /v2/ledger/sync)
	GetSyncRound(ctx echo.Context) error
	// Given a round, tells the ledger to keep that round in its cache.
	// (POST /v2/ledger/sync/{round})
	SetSyncRound(ctx echo.Context, round uint64) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// UnsetSyncRound converts echo context to params.
func (w *ServerInterfaceWrapper) UnsetSyncRound(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.UnsetSyncRound(ctx)
	return err
}

// GetSyncRound converts echo context to params.
func (w *ServerInterfaceWrapper) GetSyncRound(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetSyncRound(ctx)
	return err
}

// SetSyncRound converts echo context to params.
func (w *ServerInterfaceWrapper) SetSyncRound(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "round" -------------
	var round uint64

	err = runtime.BindStyledParameterWithLocation("simple", false, "round", runtime.ParamLocationPath, ctx.Param("round"), &round)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter round: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.SetSyncRound(ctx, round)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface, m ...echo.MiddlewareFunc) {
	RegisterHandlersWithBaseURL(router, si, "", m...)
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string, m ...echo.MiddlewareFunc) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.DELETE(baseURL+"/v2/ledger/sync", wrapper.UnsetSyncRound, m...)
	router.GET(baseURL+"/v2/ledger/sync", wrapper.GetSyncRound, m...)
	router.POST(baseURL+"/v2/ledger/sync/:round", wrapper.SetSyncRound, m...)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
