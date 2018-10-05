// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package gowsdl

var opsTmpl = `
{{range .}}
	{{$portType := .Name | makePublic}}
	type {{$portType}} struct {
		client *SOAPClient
	}

	func New{{$portType}}(url string, tls bool, auth *BasicAuth) I{{$portType}}Service {
		if url == "" {
			url = {{findServiceAddress .Name | printf "%q"}}
		}
		client := NewSOAPClient(url, tls, auth)

		return &{{$portType}}{
			client: client,
		}
	}

	func New{{$portType}}WithTLSConfig(url string, tlsCfg *tls.Config, auth *BasicAuth) I{{$portType}}Service {
		if url == "" {
			url = {{findServiceAddress .Name | printf "%q"}}
		}
		client := NewSOAPClientWithTLSConfig(url, tlsCfg, auth)

		return &{{$portType}}{
			client: client,
		}
	}

	func New{{$portType}}WithTransport(url string, tr *http.Transport, auth *BasicAuth) I{{$portType}}Service {
		if url == "" {
			url = {{findServiceAddress .Name | printf "%q"}}
		}
		client := NewSOAPClientWithTransport(url, tr, auth)

		return &{{$portType}}{
			client: client,
		}
	}

	func (service *{{$portType}}) AddHeader(header interface{}) {
		service.client.AddHeader(header)
	}

	// Backwards-compatible function: use AddHeader instead
	func (service *{{$portType}}) SetHeader(header interface{}) {
		service.client.AddHeader(header)
	}

	func (service *{{$portType}}) GetClient() *SOAPClient {
		return service.client
	}

	type I{{$portType}} interface {
	{{range .Operations}}
		{{$faults := len .Faults}}
		{{$requestType := findType .Input.Message | replaceReservedWords | makePublic}}
		{{$soapAction := findSOAPAction .Name $portType}}
		{{$responseType := findType .Output.Message | replaceReservedWords | makePublic}}

		{{/*if ne $soapAction ""*/}}
		{{if gt $faults 0}}
		// Error can be either of the following types:
		// {{range .Faults}}
		//   - {{.Name}} {{.Doc}}{{end}}{{end}}
		{{if ne .Doc ""}}/* {{.Doc}} */{{end}}
		{{makePublic .Name | replaceReservedWords}} (ctx context.Context, {{if ne $requestType ""}}request *{{$requestType}}{{end}}) (*{{$responseType}}, error)
		{{/*end*/}}
	{{end}}
	}

	type I{{$portType}}Service interface {
		I{{$portType}}
		AddHeader(header interface{})
		SetHeader(header interface{})
		GetClient() *SOAPClient
	}

	{{range .Operations}}
		{{$faults := len .Faults}}
		{{$requestType := findType .Input.Message | replaceReservedWords | makePublic}}
		{{$soapAction := findSOAPAction .Name $portType}}
		{{$responseType := findType .Output.Message | replaceReservedWords | makePublic}}

		{{/*if ne $soapAction ""*/}}
		{{if gt $faults 0}}
		// Error can be either of the following types:
		// {{range .Faults}}
		//   - {{.Name}} {{.Doc}}{{end}}{{end}}
		{{if ne .Doc ""}}/* {{.Doc}} */{{end}}
		func (service *{{$portType}}) {{makePublic .Name | replaceReservedWords}} (ctx context.Context, {{if ne $requestType ""}}request *{{$requestType}}{{end}}) (*{{$responseType}}, error) {
			response := new({{$responseType}})
			err := service.client.Call(ctx, "{{$soapAction}}", {{if ne $requestType ""}}request{{else}}nil{{end}}, response)
			if err != nil {
				return nil, err
			}

			return response, nil
		}
		{{/*end*/}}
	{{end}}
{{end}}
`
