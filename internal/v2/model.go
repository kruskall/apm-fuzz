// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package v2

import (
	"net/http"
	"time"
	"encoding/json"

)

var (
	patternAlphaNumericExt = `^[a-zA-Z0-9 _-]+$`
	patternNoAsteriskQuote = `^[^*"]*$` //do not allow '*' '"'

	enumOutcome = []string{"success", "failure", "unknown"}
)

// entry points

// errorRoot requires an error event to be present
type ErrorRoot struct {
	Error errorEvent `json:"error,omitempty" validate:"required,omitempty"`
}

// metadatatRoot requires a metadata event to be present
type MetadataRoot struct {
	Metadata metadata `json:"metadata,omitempty" validate:"required,omitempty"`
}

// metricsetRoot requires a metricset event to be present
type MetricsetRoot struct {
	Metricset metricset `json:"metricset,omitempty" validate:"required,omitempty"`
}

// spanRoot requires a span event to be present
type SpanRoot struct {
	Span span `json:"span,omitempty" validate:"required,omitempty"`
}

// transactionRoot requires a transaction event to be present
type TransactionRoot struct {
	Transaction transaction `json:"transaction,omitempty" validate:"required,omitempty"`
}

// logRoot requires a log event to be present
type LogRoot struct {
	Log log `json:"log,omitempty" validate:"required,omitempty"`
}

// other structs

type context struct {
	// Custom can contain additional metadata to be stored with the event.
	// The format is unspecified and can be deeply nested objects.
	// The information will not be indexed or searchable in Elasticsearch.
	Custom map[string]any `json:"custom,omitempty"`
	// Tags are a flat mapping of user-defined tags. On the agent side, tags
	// are called labels. Allowed value types are string, boolean and number
	// values. Tags are indexed and searchable.
	Tags map[string]any `json:"tags,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Service related information can be sent per event. Information provided
	// here will override the more generic information retrieved from metadata,
	// missing service fields will be retrieved from the metadata information.
	Service contextService `json:"service,omitempty"`
	// Cloud holds fields related to the cloud or infrastructure the events
	// are coming from.
	Cloud contextCloud `json:"cloud,omitempty"`
	// User holds information about the correlated user for this event. If
	// user data are provided here, all user related information from metadata
	// is ignored, otherwise the metadata's user information will be stored
	// with the event.
	User user `json:"user,omitempty"`
	// Page holds information related to the current page and page referers.
	// It is only sent from RUM agents.
	Page contextPage `json:"page,omitempty"`
	// Request describes the HTTP request information in case the event was
	// created as a result of an HTTP request.
	Request contextRequest `json:"request,omitempty"`
	// Message holds details related to message receiving and publishing
	// if the captured event integrates with a messaging system
	Message contextMessage `json:"message,omitempty"`
	// Response describes the HTTP response information in case the event was
	// created as a result of an HTTP request.
	Response contextResponse `json:"response,omitempty"`
}

type faas struct {
	// A unique identifier of the invoked serverless function.
	ID *string `json:"id,omitempty"`
	// The request id of the function invocation.
	Execution *string `json:"execution,omitempty"`
	// Trigger attributes.
	Trigger trigger `json:"trigger,omitempty"`
	// The lambda function name.
	Name *string `json:"name,omitempty"`
	// The lambda function version.
	Version *string `json:"version,omitempty"`
	// Indicates whether a function invocation was a cold start or not.
	Coldstart *bool `json:"coldstart,omitempty"`
}

type trigger struct {
	// The trigger type.
	Type *string `json:"type,omitempty"`
	// The id of the origin trigger request.
	RequestID *string `json:"request_id,omitempty"`
}

type contextCloud struct {
	// Origin contains the self-nested field groups for cloud.
	Origin contextCloudOrigin `json:"origin,omitempty"`
}

type contextCloudOrigin struct {
	// The cloud account or organization id used to identify
	// different entities in a multi-tenant environment.
	Account contextCloudOriginAccount `json:"account,omitempty"`
	// Name of the cloud provider.
	Provider *string `json:"provider,omitempty"`
	// Region in which this host, resource, or service is located.
	Region *string `json:"region,omitempty"`
	// The cloud service name is intended to distinguish services running
	// on different platforms within a provider.
	Service contextCloudOriginService `json:"service,omitempty"`
}

type contextCloudOriginAccount struct {
	// The cloud account or organization id used to identify
	// different entities in a multi-tenant environment.
	ID *string `json:"id,omitempty"`
}

type contextCloudOriginService struct {
	// The cloud service name is intended to distinguish services running
	// on different platforms within a provider.
	Name *string `json:"name,omitempty"`
}

type contextMessage struct {
	// Headers received with the message, similar to HTTP request headers.
	Headers *http.Header `json:"headers,omitempty"`
	// Body of the received message, similar to an HTTP request body
	Body *string `json:"body,omitempty"`
	// Queue holds information about the message queue where the message is received.
	Queue contextMessageQueue `json:"queue,omitempty"`
	// RoutingKey holds the optional routing key of the received message as set
	// on the queuing system, such as in RabbitMQ.
	RoutingKey *string `json:"routing_key,omitempty"`
	// Age of the message. If the monitored messaging framework provides a
	// timestamp for the message, agents may use it. Otherwise, the sending
	// agent can add a timestamp in milliseconds since the Unix epoch to the
	// message's metadata to be retrieved by the receiving agent. If a
	// timestamp is not available, agents should omit this field.
	Age contextMessageAge `json:"age,omitempty"`
}

type contextMessageAge struct {
	// Age of the message in milliseconds.
	Milliseconds *int `json:"ms,omitempty"`
}

type contextMessageQueue struct {
	// Name holds the name of the message queue where the message is received.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextPage struct {
	// Referer holds the URL of the page that 'linked' to the current page.
	Referer *string `json:"referer,omitempty"`
	// URL of the current page
	URL *string `json:"url,omitempty"`
}

type contextRequest struct {
	// Cookies used by the request, parsed as key-value objects.
	Cookies map[string]any `json:"cookies,omitempty"`
	// Env holds environment variable information passed to the monitored service.
	Env map[string]any `json:"env,omitempty"`
	// Body only contais the request bod, not the query string information.
	// It can either be a dictionary (for standard HTTP requests) or a raw
	// request body.
	Body any `json:"body,omitempty" validate:"inputTypes=string;object,omitempty"`
	// Headers includes any HTTP headers sent by the requester. Cookies will
	// be taken by headers if supplied.
	Headers *http.Header `json:"headers,omitempty"`
	// URL holds information sucha as the raw URL, scheme, host and path.
	URL contextRequestURL `json:"url,omitempty"`
	// HTTPVersion holds information about the used HTTP version.
	HTTPVersion *string `json:"http_version,omitempty" validate:"maxLength=1024,omitempty"`
	// Method holds information about the method of the HTTP request.
	Method *string `json:"method,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Socket holds information related to the recorded request,
	// such as whether or not data were encrypted and the remote address.
	Socket contextRequestSocket `json:"socket,omitempty"`
}

type contextRequestURL struct {
	// Port of the request, e.g. '443'. Can be sent as string or int.
	Port any `json:"port,omitempty" validate:"inputTypes=string;int,targetType=int,maxLength=1024,omitempty"`
	// Full, possibly agent-assembled URL of the request,
	// e.g. https://example.com:443/search?q=elasticsearch#top.
	Full *string `json:"full,omitempty" validate:"maxLength=1024,omitempty"`
	// Hash of the request URL, e.g. 'top'
	Hash *string `json:"hash,omitempty" validate:"maxLength=1024,omitempty"`
	// Hostname information of the request, e.g. 'example.com'."
	Hostname *string `json:"hostname,omitempty" validate:"maxLength=1024,omitempty"`
	// Path of the request, e.g. '/search'
	Path *string `json:"pathname,omitempty" validate:"maxLength=1024,omitempty"`
	// Protocol information for the recorded request, e.g. 'https:'.
	Protocol *string `json:"protocol,omitempty" validate:"maxLength=1024,omitempty"`
	// Raw unparsed URL of the HTTP request line,
	// e.g https://example.com:443/search?q=elasticsearch. This URL may be
	// absolute or relative. For more details, see
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2.
	Raw *string `json:"raw,omitempty" validate:"maxLength=1024,omitempty"`
	// Search contains the query string information of the request. It is
	// expected to have values delimited by ampersands.
	Search *string `json:"search,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextRequestSocket struct {
	// RemoteAddress holds the network address sending the request. It should
	// be obtained through standard APIs and not be parsed from any headers
	// like 'Forwarded'.
	RemoteAddress *string `json:"remote_address,omitempty"`
	// Encrypted indicates whether a request was sent as TLS/HTTPS request.
	// DEPRECATED: this field will be removed in a future release.
	Encrypted *bool `json:"encrypted,omitempty"`
}

type contextResponse struct {
	// Headers holds the http headers sent in the http response.
	Headers *http.Header `json:"headers,omitempty"`
	// StatusCode sent in the http response.
	StatusCode *int `json:"status_code,omitempty"`
	// TransferSize holds the total size of the payload.
	TransferSize *int `json:"transfer_size,omitempty"`
	// DecodedBodySize holds the size of the decoded payload.
	DecodedBodySize *int `json:"decoded_body_size,omitempty"`
	// EncodedBodySize holds the size of the encoded payload.
	EncodedBodySize *int `json:"encoded_body_size,omitempty"`
	// Finished indicates whether the response was finished or not.
	Finished *bool `json:"finished,omitempty"`
	// HeadersSent indicates whether http headers were sent.
	HeadersSent *bool `json:"headers_sent,omitempty"`
}

type contextService struct {
	// Agent holds information about the APM agent capturing the event.
	Agent contextServiceAgent `json:"agent,omitempty"`
	// Environment in which the monitored service is running,
	// e.g. `production` or `staging`.
	Environment *string `json:"environment,omitempty" validate:"maxLength=1024,omitempty"`
	// Framework holds information about the framework used in the
	// monitored service.
	Framework contextServiceFramework `json:"framework,omitempty"`
	// ID holds a unique identifier for the service.
	ID *string `json:"id,omitempty"`
	// Language holds information about the programming language of the
	// monitored service.
	Language contextServiceLanguage `json:"language,omitempty"`
	// Name of the monitored service.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,pattern=patternAlphaNumericExt,omitempty"`
	// Node must be a unique meaningful name of the service node.
	Node contextServiceNode `json:"node,omitempty"`
	// Origin contains the self-nested field groups for service.
	Origin contextServiceOrigin `json:"origin,omitempty"`
	// Runtime holds information about the language runtime running the
	// monitored service
	Runtime contextServiceRuntime `json:"runtime,omitempty"`
	// Target holds information about the outgoing service in case of
	// an outgoing event
	Target contextServiceTarget `json:"target,omitempty"`
	// Version of the monitored service.
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceTarget struct {
	// _ struct{} // removed `validate:"requiredAnyOf=type;name,omitempty"`
	// Immutable name of the target service for the event
	Name *string `json:"name,omitempty"`
	// Immutable type of the target service for the event
	Type *string `json:"type,omitempty"`
}

type contextServiceOrigin struct {
	// Immutable id of the service emitting this event.
	ID *string `json:"id,omitempty"`
	// Immutable name of the service emitting this event.
	Name *string `json:"name,omitempty"`
	// The version of the service the data was collected from.
	Version *string `json:"version,omitempty"`
}

type contextServiceAgent struct {
	// EphemeralID is a free format ID used for metrics correlation by agents
	EphemeralID *string `json:"ephemeral_id,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the APM agent capturing information.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the APM agent capturing information.
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceFramework struct {
	// Name of the used framework
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the used framework
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceLanguage struct {
	// Name of the used programming language
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the used programming language
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceNode struct {
	// Name of the service node
	Name *string `json:"configured_name,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceRuntime struct {
	// Name of the language runtime
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the language runtime
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

// errorEvent represents an error or a logged error message,
// captured by an APM agent in a monitored service.
type errorEvent struct {
	// _ struct{} // removed `validate:"requiredAnyOf=exception;log,omitempty"`
	// Timestamp holds the recorded time of the event, UTC based and formatted
	// as microseconds since Unix epoch.
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Log holds additional information added when the error is logged.
	Log errorLog `json:"log,omitempty"`
	// Culprit identifies the function call which was the primary perpetrator
	// of this event.
	Culprit *string `json:"culprit,omitempty" validate:"maxLength=1024,omitempty"`
	// ID holds the hex encoded 128 random bits ID of the event.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// ParentID holds the hex encoded 64 random bits ID of the parent
	// transaction or span.
	ParentID *string `json:"parent_id,omitempty" validate:"requiredIfAny=transaction_id;trace_id,maxLength=1024,omitempty"`
	// TraceID holds the hex encoded 128 random bits ID of the correlated trace.
	TraceID *string `json:"trace_id,omitempty" validate:"requiredIfAny=transaction_id;parent_id,maxLength=1024,omitempty"`
	// TransactionID holds the hex encoded 64 random bits ID of the correlated
	// transaction.
	TransactionID *string `json:"transaction_id,omitempty" validate:"maxLength=1024,omitempty"`
	// Exception holds information about the original error.
	// The information is language specific.
	Exception errorException `json:"exception,omitempty"`
	// Transaction holds information about the correlated transaction.
	Transaction errorTransactionRef `json:"transaction,omitempty"`
	// Context holds arbitrary contextual information for the event.
	Context context `json:"context,omitempty"`
}

type errorException struct {
	// _ struct{} // removed `validate:"requiredAnyOf=message;type,omitempty"`
	// Attributes of the exception.
	Attributes map[string]any `json:"attributes,omitempty"`
	// Code that is set when the error happened, e.g. database error code.
	Code any `json:"code,omitempty" validate:"inputTypes=string;int,maxLength=1024,omitempty"`
	// Cause can hold a collection of error exceptions representing chained
	// exceptions. The chain starts with the outermost exception, followed
	// by its cause, and so on.
	Cause []errorException `json:"cause,omitempty"`
	// Stacktrace information of the captured exception.
	Stacktrace []stacktraceFrame `json:"stacktrace,omitempty"`
	// Message contains the originally captured error message.
	Message *string `json:"message,omitempty"`
	// Module describes the exception type's module namespace.
	Module *string `json:"module,omitempty" validate:"maxLength=1024,omitempty"`
	// Type of the exception.
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
	// Handled indicates whether the error was caught in the code or not.
	Handled *bool `json:"handled,omitempty"`
}

type errorLog struct {
	// Level represents the severity of the recorded log.
	Level *string `json:"level,omitempty" validate:"maxLength=1024,omitempty"`
	// LoggerName holds the name of the used logger instance.
	LoggerName *string `json:"logger_name,omitempty" validate:"maxLength=1024,omitempty"`
	// Message of the logged error. In case a parameterized message is captured,
	// Message should contain the same information, but with any placeholders
	// being replaced.
	Message *string `json:"message,omitempty" validate:"required,omitempty"`
	// ParamMessage should contain the same information as Message, but with
	// placeholders where parameters were logged, e.g. 'error connecting to %s'.
	// The string is not interpreted, allowing differnt placeholders per client
	// languange. The information might be used to group errors together.
	ParamMessage *string `json:"param_message,omitempty" validate:"maxLength=1024,omitempty"`
	// Stacktrace information of the captured error.
	Stacktrace []stacktraceFrame `json:"stacktrace,omitempty"`
}

type errorTransactionRef struct {
	// Name is the generic designation of a transaction in the scope of a
	// single service, eg: 'GET /users/:id'.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Type expresses the correlated transaction's type as keyword that has
	// specific relevance within the service's domain,
	// eg: 'request', 'backgroundjob'.
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
	// Sampled indicates whether or not the full information for a transaction
	// is captured. If a transaction is unsampled no spans and less context
	// information will be reported.
	Sampled *bool `json:"sampled,omitempty"`
}

type metadata struct {
	// Labels are a flat mapping of user-defined tags. Allowed value types are
	// string, boolean and number values. Labels are indexed and searchable.
	Labels map[string]any `json:"labels,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Service metadata about the monitored service.
	Service metadataService `json:"service,omitempty" validate:"required,omitempty"`
	// Cloud metadata about where the monitored service is running.
	Cloud metadataCloud `json:"cloud,omitempty"`
	// System metadata
	System metadataSystem `json:"system,omitempty"`
	// User metadata, which can be overwritten on a per event basis.
	User user `json:"user,omitempty"`
	// Network holds information about the network over which the
	// monitored service is communicating.
	Network network `json:"network,omitempty"`
	// Process metadata about the monitored service.
	Process metadataProcess `json:"process,omitempty"`
}

type metadataCloud struct {
	// Account where the monitored service is running.
	Account metadataCloudAccount `json:"account,omitempty"`
	// AvailabilityZone where the monitored service is running, e.g. us-east-1a
	AvailabilityZone *string `json:"availability_zone,omitempty" validate:"maxLength=1024,omitempty"`
	// Instance on which the monitored service is running.
	Instance metadataCloudInstance `json:"instance,omitempty"`
	// Machine on which the monitored service is running.
	Machine metadataCloudMachine `json:"machine,omitempty"`
	// Project in which the monitored service is running.
	Project metadataCloudProject `json:"project,omitempty"`
	// Provider that is used, e.g. aws, azure, gcp, digitalocean.
	Provider *string `json:"provider,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Region where the monitored service is running, e.g. us-east-1
	Region *string `json:"region,omitempty" validate:"maxLength=1024,omitempty"`
	// Service that is monitored on cloud
	Service metadataCloudService `json:"service,omitempty"`
}

type metadataCloudAccount struct {
	// ID of the cloud account.
	ID *string `json:"id,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the cloud account.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataCloudInstance struct {
	// ID of the cloud instance.
	ID *string `json:"id,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the cloud instance.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataCloudMachine struct {
	// ID of the cloud machine.
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataCloudProject struct {
	// ID of the cloud project.
	ID *string `json:"id,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the cloud project.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataCloudService struct {
	// Name of the cloud service, intended to distinguish services running on
	// different platforms within a provider, eg AWS EC2 vs Lambda,
	// GCP GCE vs App Engine, Azure VM vs App Server.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataProcess struct {
	// Argv holds the command line arguments used to start this process.
	Argv []string `json:"argv,omitempty"`
	// Title is the process title. It can be the same as process name.
	Title *string `json:"title,omitempty" validate:"maxLength=1024,omitempty"`
	// PID holds the process ID of the service.
	Pid *int `json:"pid,omitempty" validate:"required,omitempty"`
	// Ppid holds the parent process ID of the service.
	Ppid *int `json:"ppid,omitempty"`
}

type metadataService struct {
	// Agent holds information about the APM agent capturing the event.
	Agent metadataServiceAgent `json:"agent,omitempty" validate:"required,omitempty"`
	// Environment in which the monitored service is running,
	// e.g. `production` or `staging`.
	Environment *string `json:"environment,omitempty" validate:"maxLength=1024,omitempty"`
	// Framework holds information about the framework used in the
	// monitored service.
	Framework metadataServiceFramework `json:"framework,omitempty"`
	// ID holds a unique identifier for the running service.
	ID *string `json:"id,omitempty"`
	// Language holds information about the programming language of the
	// monitored service.
	Language metadataServiceLanguage `json:"language,omitempty"`
	// Name of the monitored service.
	Name *string `json:"name,omitempty" validate:"required,minLength=1,maxLength=1024,pattern=patternAlphaNumericExt,omitempty"`
	// Node must be a unique meaningful name of the service node.
	Node metadataServiceNode `json:"node,omitempty"`
	// Runtime holds information about the language runtime running the
	// monitored service
	Runtime metadataServiceRuntime `json:"runtime,omitempty"`
	// Version of the monitored service.
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceAgent struct {
	// ActivationMethod of the APM agent capturing information.
	ActivationMethod *string `json:"activation_method,omitempty" validate:"maxLength=1024,omitempty"`
	// EphemeralID is a free format ID used for metrics correlation by agents
	EphemeralID *string `json:"ephemeral_id,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the APM agent capturing information.
	Name *string `json:"name,omitempty" validate:"required,minLength=1,maxLength=1024,omitempty"`
	// Version of the APM agent capturing information.
	Version *string `json:"version,omitempty" validate:"required,maxLength=1024,omitempty"`
}

type metadataServiceFramework struct {
	// Name of the used framework
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the used framework
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceLanguage struct {
	// Name of the used programming language
	Name *string `json:"name,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Version of the used programming language
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceNode struct {
	// Name of the service node
	Name *string `json:"configured_name,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceRuntime struct {
	// Name of the language runtime
	Name *string `json:"name,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Name of the language runtime
	Version *string `json:"version,omitempty" validate:"required,maxLength=1024,omitempty"`
}

type metadataSystem struct {
	// Architecture of the system the monitored service is running on.
	Architecture *string `json:"architecture,omitempty" validate:"maxLength=1024,omitempty"`
	// ConfiguredHostname is the configured name of the host the monitored
	// service is running on. It should only be sent when configured by the
	// user. If given, it is used as the event's hostname.
	ConfiguredHostname *string `json:"configured_hostname,omitempty" validate:"maxLength=1024,omitempty"`
	// Container holds the system's container ID if available.
	Container metadataSystemContainer `json:"container,omitempty"`
	// DetectedHostname is the hostname detected by the APM agent. It usually
	// contains what the hostname command returns on the host machine.
	// It will be used as the event's hostname if ConfiguredHostname is not present.
	DetectedHostname *string `json:"detected_hostname,omitempty" validate:"maxLength=1024,omitempty"`
	// Deprecated: Use ConfiguredHostname and DetectedHostname instead.
	// DeprecatedHostname is the host name of the system the service is
	// running on. It does not distinguish between configured and detected
	// hostname and therefore is deprecated and only used if no other hostname
	// information is available.
	DeprecatedHostname *string `json:"hostname,omitempty" validate:"maxLength=1024,omitempty"`
	// Kubernetes system information if the monitored service runs on Kubernetes.
	Kubernetes metadataSystemKubernetes `json:"kubernetes,omitempty"`
	// Platform name of the system platform the monitored service is running on.
	Platform *string `json:"platform,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataSystemContainer struct {
	// ID of the container the monitored service is running in.
	ID *string `json:"id,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataSystemKubernetes struct {
	// Namespace of the Kubernetes resource the monitored service is run on.
	Namespace *string `json:"namespace,omitempty" validate:"maxLength=1024,omitempty"`
	// Node related information
	Node metadataSystemKubernetesNode `json:"node,omitempty"`
	// Pod related information
	Pod metadataSystemKubernetesPod `json:"pod,omitempty"`
}

type metadataSystemKubernetesNode struct {
	// Name of the Kubernetes Node
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataSystemKubernetesPod struct {
	// Name of the Kubernetes Pod
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// UID is the system-generated string uniquely identifying the Pod.
	UID *string `json:"uid,omitempty" validate:"maxLength=1024,omitempty"`
}

type network struct {
	Connection networkConnection `json:"connection,omitempty"`
}

type networkConnection struct {
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
}

type metricset struct {
	// Timestamp holds the recorded time of the event, UTC based and formatted
	// as microseconds since Unix epoch
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Samples hold application metrics collected from the agent.
	Samples map[string]metricsetSampleValue `json:"samples,omitempty" validate:"required,patternKeys=patternNoAsteriskQuote,omitempty"`
	// Span holds selected information about the correlated transaction.
	Span metricsetSpanRef `json:"span,omitempty"`
	// Tags are a flat mapping of user-defined tags. On the agent side, tags
	// are called labels. Allowed value types are string, boolean and number
	// values. Tags are indexed and searchable.
	Tags map[string]any `json:"tags,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Transaction holds selected information about the correlated transaction.
	Transaction metricsetTransactionRef `json:"transaction,omitempty"`
	// Service holds selected information about the correlated service.
	Service metricsetServiceRef `json:"service,omitempty"`
	// FAAS holds fields related to Function as a Service events.
	FAAS faas `json:"faas,omitempty"`
}

type metricsetSampleValue struct {
	// At least one of value or values must be specified.
	// _ struct{} // removed `validate:"requiredAnyOf=value;values,omitempty"`
	// Type holds an optional metric type: gauge, counter, or histogram.
	//
	// If Type is unknown, it will be ignored.
	Type *string `json:"type,omitempty"`

	// Unit holds an optional unit for the metric.
	//
	// - "percent" (value is in the range [0,1])
	// - "byte"
	// - a time unit: "nanos", "micros", "ms", "s", "m", "h", "d"
	//
	// If Unit is unknown, it will be ignored.
	Unit *string `json:"unit,omitempty"`

	// Values holds the bucket values for histogram metrics.
	//
	// Values must be provided in ascending order; failure to do
	// so will result in the metric being discarded.
	Values []float64 `json:"values,omitempty" validate:"requiredIfAny=counts,omitempty"`

	// Counts holds the bucket counts for histogram metrics.
	//
	// These numbers must be positive or zero.
	//
	// If Counts is specified, then Values is expected to be
	// specified with the same number of elements, and with the
	// same order.
	Counts []int64 `json:"counts,omitempty" validate:"requiredIfAny=values,minVals=0,omitempty"`
	// Value holds the value of a single metric sample.
	Value *float64 `json:"value,omitempty"`
}

type metricsetSpanRef struct {
	// Subtype is a further sub-division of the type (e.g. postgresql, elasticsearch)
	Subtype *string `json:"subtype,omitempty" validate:"maxLength=1024,omitempty"`
	// Type expresses the correlated span's type as keyword that has specific
	// relevance within the service's domain, eg: 'request', 'backgroundjob'.
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
}

type metricsetTransactionRef struct {
	// Name of the correlated transaction.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Type expresses the correlated transaction's type as keyword that has specific
	// relevance within the service's domain, eg: 'request', 'backgroundjob'.
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
}

type metricsetServiceRef struct {
	// Name of the correlated service.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the correlated service.
	Version *string `json:"version,omitempty" validate:"maxLength=1024,omitempty"`
}

type span struct {
	// _ struct{} // removed `validate:"requiredAnyOf=start;timestamp,omitempty"`
	// Timestamp holds the recorded time of the event, UTC based and formatted
	// as microseconds since Unix epoch
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// OTel contains unmapped OpenTelemetry attributes.
	OTel otel `json:"otel,omitempty"`
	// ID holds the hex encoded 64 random bits ID of the event.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// TraceID holds the hex encoded 128 random bits ID of the correlated trace.
	TraceID *string `json:"trace_id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Action holds the specific kind of event within the sub-type represented
	// by the span (e.g. query, connect)
	Action *string `json:"action,omitempty" validate:"maxLength=1024,omitempty"`
	// Name is the generic designation of a span in the scope of a transaction.
	Name *string `json:"name,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Outcome of the span: success, failure, or unknown. Outcome may be one of
	// a limited set of permitted values describing the success or failure of
	// the span. It can be used for calculating error rates for outgoing requests.
	Outcome *string `json:"outcome,omitempty" validate:"enum=enumOutcome,omitempty"`
	// ChildIDs holds a list of successor transactions and/or spans.
	ChildIDs []string `json:"child_ids,omitempty" validate:"maxLength=1024,omitempty"`
	// ParentID holds the hex encoded 64 random bits ID of the parent
	// transaction or span.
	ParentID *string `json:"parent_id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Links holds links to other spans, potentially in other traces.
	Links []spanLink `json:"links,omitempty"`
	// Stacktrace connected to this span event.
	Stacktrace []stacktraceFrame `json:"stacktrace,omitempty"`
	// Type holds the span's type, and can have specific keywords
	// within the service's domain (eg: 'request', 'backgroundjob', etc)
	Type *string `json:"type,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Subtype is a further sub-division of the type (e.g. postgresql, elasticsearch)
	Subtype *string `json:"subtype,omitempty" validate:"maxLength=1024,omitempty"`
	// TransactionID holds the hex encoded 64 random bits ID of the correlated
	// transaction.
	TransactionID *string `json:"transaction_id,omitempty" validate:"maxLength=1024,omitempty"`
	// Composite holds details on a group of spans represented by a single one.
	Composite spanComposite `json:"composite,omitempty"`
	// Context holds arbitrary contextual information for the event.
	Context spanContext `json:"context,omitempty"`
	// Start is the offset relative to the transaction's timestamp identifying
	// the start of the span, in milliseconds.
	Start *float64 `json:"start,omitempty"`
	// SampleRate applied to the monitored service at the time where this span
	// was recorded.
	SampleRate *float64 `json:"sample_rate,omitempty"`
	// Duration of the span in milliseconds. When the span is a composite one,
	// duration is the gross duration, including "whitespace" in between spans.
	Duration *float64 `json:"duration,omitempty" validate:"required,min=0,omitempty"`
	// Sync indicates whether the span was executed synchronously or asynchronously.
	Sync *bool `json:"sync,omitempty"`
}

type spanContext struct {
	// Tags are a flat mapping of user-defined tags. On the agent side, tags
	// are called labels. Allowed value types are string, boolean and number
	// values. Tags are indexed and searchable.
	Tags map[string]any `json:"tags,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Service related information can be sent per span. Information provided
	// here will override the more generic information retrieved from metadata,
	// missing service fields will be retrieved from the metadata information.
	Service contextService `json:"service,omitempty"`
	// Message holds details related to message receiving and publishing
	// if the captured event integrates with a messaging system
	Message contextMessage `json:"message,omitempty"`
	// Database contains contextual data for database spans
	Database spanContextDatabase `json:"db,omitempty"`
	// Destination contains contextual data about the destination of spans
	Destination spanContextDestination `json:"destination,omitempty"`
	// HTTP contains contextual information when the span concerns an HTTP request.
	HTTP spanContextHTTP `json:"http,omitempty"`
}

type spanContextDatabase struct {
	// Instance name of the database.
	Instance *string `json:"instance,omitempty"`
	// Link to the database server.
	Link *string `json:"link,omitempty" validate:"maxLength=1024,omitempty"`
	// Statement of the recorded database event, e.g. query.
	Statement *string `json:"statement,omitempty"`
	// Type of the recorded database event., e.g. sql, cassandra, hbase, redis.
	Type *string `json:"type,omitempty"`
	// User is the username with which the database is accessed.
	User *string `json:"user,omitempty"`
	// RowsAffected shows the number of rows affected by the statement.
	RowsAffected *int `json:"rows_affected,omitempty"`
}

type spanContextDestination struct {
	// Service describes the destination service
	Service spanContextDestinationService `json:"service,omitempty"`
	// Address is the destination network address:
	// hostname (e.g. 'localhost'),
	// FQDN (e.g. 'elastic.co'),
	// IPv4 (e.g. '127.0.0.1')
	// IPv6 (e.g. '::1')
	Address *string `json:"address,omitempty" validate:"maxLength=1024,omitempty"`
	// Port is the destination network port (e.g. 443)
	Port *int `json:"port,omitempty"`
}

type spanContextDestinationService struct {
	// Name is the identifier for the destination service,
	// e.g. 'http://elastic.co', 'elasticsearch', 'rabbitmq' (
	// DEPRECATED: this field will be removed in a future release
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Resource identifies the destination service resource being operated on
	// e.g. 'http://elastic.co:80', 'elasticsearch', 'rabbitmq/queue_name'
	// DEPRECATED: this field will be removed in a future release
	Resource *string `json:"resource,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Type of the destination service, e.g. db, elasticsearch. Should
	// typically be the same as span.type.
	// DEPRECATED: this field will be removed in a future release
	Type *string `json:"type,omitempty" validate:"maxLength=1024,omitempty"`
}

type spanContextHTTP struct {
	// Request describes the HTTP request information.
	Request spanContextHTTPRequest `json:"request,omitempty"`
	// Method holds information about the method of the HTTP request.
	Method *string `json:"method,omitempty" validate:"maxLength=1024,omitempty"`
	// URL is the raw url of the correlating HTTP request.
	URL *string `json:"url,omitempty"`
	// Response describes the HTTP response information in case the event was
	// created as a result of an HTTP request.
	Response spanContextHTTPResponse `json:"response,omitempty"`
	// Deprecated: Use Response.StatusCode instead.
	// StatusCode sent in the http response.
	StatusCode *int `json:"status_code,omitempty"`
}

type spanContextHTTPRequest struct {
	// ID holds the unique identifier for the http request.
	ID *string `json:"id,omitempty"`
}

type spanContextHTTPResponse struct {
	// Headers holds the http headers sent in the http response.
	Headers *http.Header `json:"headers,omitempty"`
	// DecodedBodySize holds the size of the decoded payload.
	DecodedBodySize *int `json:"decoded_body_size,omitempty"`
	// EncodedBodySize holds the size of the encoded payload.
	EncodedBodySize *int `json:"encoded_body_size,omitempty"`
	// StatusCode sent in the http response.
	StatusCode *int `json:"status_code,omitempty"`
	// TransferSize holds the total size of the payload.
	TransferSize *int `json:"transfer_size,omitempty"`
}

type stacktraceFrame struct {
	// _ struct{} // removed `validate:"requiredAnyOf=classname;filename,omitempty"`
	// Vars is a flat mapping of local variables of the frame.
	Vars map[string]any `json:"vars,omitempty"`
	// Filename is the relative name of the frame's file.
	Filename *string `json:"filename,omitempty"`
	// AbsPath is the absolute path of the frame's file.
	AbsPath *string `json:"abs_path,omitempty"`
	// Classname of the frame.
	Classname *string `json:"classname,omitempty"`
	// ContextLine is the line from the frame's file.
	ContextLine *string `json:"context_line,omitempty"`
	// Function represented by the frame.
	Function *string `json:"function,omitempty"`
	// Module to which the frame belongs to.
	Module *string `json:"module,omitempty"`
	// PostContext is a slice of code lines immediately before the line
	// from the frame's file.
	PostContext []string `json:"post_context,omitempty"`
	// PreContext is a slice of code lines immediately after the line
	// from the frame's file.
	PreContext []string `json:"pre_context,omitempty"`
	// LineNumber of the frame.
	LineNumber *int `json:"lineno,omitempty"`
	// ColumnNumber of the frame.
	ColumnNumber *int `json:"colno,omitempty"`
	// LibraryFrame indicates whether the frame is from a third party library.
	LibraryFrame *bool `json:"library_frame,omitempty"`
}

type spanComposite struct {
	// A string value indicating which compression strategy was used. The valid
	// values are `exact_match` and `same_kind`.
	CompressionStrategy *string `json:"compression_strategy,omitempty" validate:"required,omitempty"`
	// Count is the number of compressed spans the composite span represents.
	// The minimum count is 2, as a composite span represents at least two spans.
	Count *int `json:"count,omitempty" validate:"required,min=2,omitempty"`
	// Sum is the durations of all compressed spans this composite span
	// represents in milliseconds.
	Sum *float64 `json:"sum,omitempty" validate:"required,min=0,omitempty"`
}

type transaction struct {
	// Marks capture the timing of a significant event during the lifetime of
	// a transaction. Marks are organized into groups and can be set by the
	// user or the agent. Marks are only reported by RUM agents.
	Marks transactionMarks `json:"marks,omitempty"`
	// Timestamp holds the recorded time of the event, UTC based and formatted
	// as microseconds since Unix epoch
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// OTel contains unmapped OpenTelemetry attributes.
	OTel otel `json:"otel,omitempty"`
	// Links holds links to other spans, potentially in other traces.
	Links []spanLink `json:"links,omitempty"`
	// TraceID holds the hex encoded 128 random bits ID of the correlated trace.
	TraceID *string `json:"trace_id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// ID holds the hex encoded 64 random bits ID of the event.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// ParentID holds the hex encoded 64 random bits ID of the parent
	// transaction or span.
	ParentID *string `json:"parent_id,omitempty" validate:"maxLength=1024,omitempty"`
	// Name is the generic designation of a transaction in the scope of a
	// single service, eg: 'GET /users/:id'.
	Name *string `json:"name,omitempty" validate:"maxLength=1024,omitempty"`
	// Type expresses the transaction's type as keyword that has specific
	// relevance within the service's domain, eg: 'request', 'backgroundjob'.
	Type *string `json:"type,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Result of the transaction. For HTTP-related transactions, this should
	// be the status code formatted like 'HTTP 2xx'.
	Result *string `json:"result,omitempty" validate:"maxLength=1024,omitempty"`
	// DroppedSpanStats holds information about spans that were dropped
	// (for example due to transaction_max_spans or exit_span_min_duration).
	DroppedSpanStats []transactionDroppedSpanStats `json:"dropped_spans_stats,omitempty"`
	// Outcome of the transaction with a limited set of permitted values,
	// describing the success or failure of the transaction from the service's
	// perspective. It is used for calculating error rates for incoming requests.
	// Permitted values: success, failure, unknown.
	Outcome *string `json:"outcome,omitempty" validate:"enum=enumOutcome,omitempty"`
	// FAAS holds fields related to Function as a Service events.
	FAAS faas `json:"faas,omitempty"`
	// Session holds optional transaction session information for RUM.
	Session transactionSession `json:"session,omitempty"`
	// Context holds arbitrary contextual information for the event.
	Context context `json:"context,omitempty"`
	// UserExperience holds metrics for measuring real user experience.
	// This information is only sent by RUM agents.
	UserExperience transactionUserExperience `json:"experience,omitempty"`
	// SpanCount counts correlated spans.
	SpanCount transactionSpanCount `json:"span_count,omitempty" validate:"required,omitempty"`
	// SampleRate applied to the monitored service at the time where this transaction
	// was recorded. Allowed values are [0..1]. A SampleRate <1 indicates that
	// not all spans are recorded.
	SampleRate *float64 `json:"sample_rate,omitempty"`
	// Duration how long the transaction took to complete, in milliseconds
	// with 3 decimal points.
	Duration *float64 `json:"duration,omitempty" validate:"required,min=0,omitempty"`
	// Sampled indicates whether or not the full information for a transaction
	// is captured. If a transaction is unsampled no spans and less context
	// information will be reported.
	Sampled *bool `json:"sampled,omitempty"`
}

type log struct {
	// Labels are a flat mapping of user-defined key-value pairs.
	Labels map[string]any `json:"labels,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Timestamp holds the recorded time of the event, UTC based and formatted
	// as microseconds since Unix epoch
	Timestamp *time.Time `json:"@timestamp,omitempty"`
	// Below embedded fields are added to enable supporting both nested and flat JSON.
	// This is achieved by generating code using static analysis of these structs.
	// The logic parses JSON tag of each struct field to produce a code which, at runtime,
	// checks the nested map to retrieve the required value for each field.
	EcsLogServiceFields
	EcsLogErrorFields
	EcsLogEventFields
	EcsLogProcessFields

	// TraceID holds the ID of the correlated trace.
	TraceID *string `json:"trace.id,omitempty" validate:"maxLength=1024,omitempty"`
	// TransactionID holds the ID of the correlated transaction.
	TransactionID *string `json:"transaction.id,omitempty" validate:"maxLength=1024,omitempty"`
	// SpanID holds the ID of the correlated span.
	SpanID *string `json:"span.id,omitempty" validate:"maxLength=1024,omitempty"`
	// Message logged as part of the log. In case a parameterized message is
	// captured, Message should contain the same information, but with any placeholders
	// being replaced.
	Message *string `json:"message,omitempty"`
	// FAAS holds fields related to Function as a Service events.
	FAAS faas `json:"faas,omitempty"`
	// Below embedded fields are added to enable supporting both nested and flat JSON.
	// This is achieved by generating code using static analysis of these structs.
	// The logic parses JSON tag of each struct field to produce a code which, at runtime,
	// checks the nested map to retrieve the required value for each field.
	EcsLogLogFields
}

// EcsLogEventFields holds event.* fields for supporting ECS logging format and enables
// parsing them in flat as well as nested notation.
type EcsLogEventFields struct {
	NestedStruct map[string]interface{} `json:"event" nested:"true,omitempty"`
	// ProcessThreadName represents the name of the thread.
	EventDataset *string `json:"event.dataset,omitempty" validate:"maxLength=1024,omitempty"`
}

// EcsLogProcessFields holds process.* fields for supporting ECS logging format and enables
// parsing them in flat as well as nested notation.
type EcsLogProcessFields struct {
	NestedStruct map[string]interface{} `json:"process" nested:"true,omitempty"`
	// ProcessThreadName represents the name of the thread.
	ProcessThreadName *string `json:"process.thread.name,omitempty" validate:"maxLength=1024,omitempty"`
}

// EcsLogErrorFields holds error.* fields for supporting ECS logging format and enables
// parsing them in flat as well as nested notation.
type EcsLogErrorFields struct {
	NestedStruct map[string]interface{} `json:"error" nested:"true,omitempty"`
	// ErrorType represents the type of the error if the log line represents an error.
	ErrorType *string `json:"error.type,omitempty"`
	// ErrorMessage represents the message contained in the error if the log line
	// represents an error.
	ErrorMessage *string `json:"error.message,omitempty"`
	// ErrorStacktrace represents the plain text stacktrace of the error the log line
	// represents.
	ErrorStacktrace *string `json:"error.stack_trace,omitempty"`
}

// EcsLogLogFields holds log.* fields for supporting ECS logging format and enables
// parsing them in flat as well as nested notation.
type EcsLogLogFields struct {
	NestedStruct map[string]interface{} `json:"log" nested:"true,omitempty"`
	// Level represents the severity of the recorded log.
	Level *string `json:"log.level,omitempty" validate:"maxLength=1024,omitempty"`
	// Logger represents the name of the used logger instance.
	Logger *string `json:"log.logger,omitempty" validate:"maxLength=1024,omitempty"`
	// OriginFileName represents the filename containing the sourcecode where the log
	// originated.
	OriginFileName *string `json:"log.origin.file.name,omitempty" validate:"maxLength=1024,omitempty"`
	// OriginFunction represents the function name where the log originated.
	OriginFunction *string `json:"log.origin.function,omitempty"`
	// OriginFileLine represents the line number in the file containing the sourcecode
	// where the log originated.
	OriginFileLine *int `json:"log.origin.file.line,omitempty"`
}

// EcsLogServiceFields holds service.* fields for supporting ECS logging format and
// enables parsing them in flat as well as nested notation.
type EcsLogServiceFields struct {
	NestedStruct map[string]interface{} `json:"service" nested:"true,omitempty"`
	// ServiceName represents name of the service which originated the log line.
	ServiceName *string `json:"service.name,omitempty" validate:"maxLength=1024,omitempty"`
	// ServiceVersion represents the version of the service which originated the log
	// line.
	ServiceVersion *string `json:"service.version,omitempty" validate:"maxLength=1024,omitempty"`
	// ServiceEnvironment represents the environment the service which originated the
	// log line is running in.
	ServiceEnvironment *string `json:"service.environment,omitempty" validate:"maxLength=1024,omitempty"`
	// ServiceNodeName represents a unique node name per host for the service which
	// originated the log line.
	ServiceNodeName *string `json:"service.node.name,omitempty" validate:"maxLength=1024,omitempty"`
}

type otel struct {
	// Attributes hold the unmapped OpenTelemetry attributes.
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	// SpanKind holds the incoming OpenTelemetry span kind.
	SpanKind *string `json:"span_kind,omitempty"`
}

type transactionSession struct {
	// ID holds a session ID for grouping a set of related transactions.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`

	// Sequence holds an optional sequence number for a transaction within
	// a session. It is not meaningful to compare sequences across two
	// different sessions.
	Sequence *int `json:"sequence,omitempty" validate:"min=1,omitempty"`
}

type transactionMarks struct {
	Events map[string]transactionMarkEvents `json:"-,omitempty"`
}

func (m *transactionMarks) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.Events)
}

type transactionMarkEvents struct {
	Measurements map[string]float64 `json:"-,omitempty"`
}

func (m *transactionMarkEvents) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.Measurements)
}

type transactionSpanCount struct {
	// Dropped is the number of correlated spans that have been dropped by
	// the APM agent recording the transaction.
	Dropped *int `json:"dropped,omitempty"`
	// Started is the number of correlated spans that are recorded.
	Started *int `json:"started,omitempty" validate:"required,omitempty"`
}

// transactionUserExperience holds real user (browser) experience metrics.
type transactionUserExperience struct {
	// CumulativeLayoutShift holds the Cumulative Layout Shift (CLS) metric value,
	// or a negative value if CLS is unknown. See https://web.dev/cls/
	CumulativeLayoutShift *float64 `json:"cls,omitempty" validate:"min=0,omitempty"`
	// FirstInputDelay holds the First Input Delay (FID) metric value,
	// or a negative value if FID is unknown. See https://web.dev/fid/
	FirstInputDelay *float64 `json:"fid,omitempty" validate:"min=0,omitempty"`
	// Longtask holds longtask duration/count metrics.
	Longtask longtaskMetrics `json:"longtask,omitempty"`
	// TotalBlockingTime holds the Total Blocking Time (TBT) metric value,
	// or a negative value if TBT is unknown. See https://web.dev/tbt/
	TotalBlockingTime *float64 `json:"tbt,omitempty" validate:"min=0,omitempty"`
}

type longtaskMetrics struct {
	// Count is the total number of of longtasks.
	Count *int `json:"count,omitempty" validate:"required,min=0,omitempty"`
	// Max longtask duration
	Max *float64 `json:"max,omitempty" validate:"required,min=0,omitempty"`
	// Sum of longtask durations
	Sum *float64 `json:"sum,omitempty" validate:"required,min=0,omitempty"`
}

type user struct {
	// Domain of the logged in user
	Domain *string `json:"domain,omitempty" validate:"maxLength=1024,omitempty"`
	// ID identifies the logged in user, e.g. can be the primary key of the user
	ID any `json:"id,omitempty" validate:"maxLength=1024,inputTypes=string;int,omitempty"`
	// Email of the user.
	Email *string `json:"email,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the user.
	Name *string `json:"username,omitempty" validate:"maxLength=1024,omitempty"`
}

type transactionDroppedSpanStats struct {
	// DestinationServiceResource identifies the destination service resource
	// being operated on. e.g. 'http://elastic.co:80', 'elasticsearch', 'rabbitmq/queue_name'.
	DestinationServiceResource *string `json:"destination_service_resource,omitempty" validate:"maxLength=1024,omitempty"`
	// ServiceTargetType identifies the type of the target service being operated on
	// e.g. 'oracle', 'rabbitmq'
	ServiceTargetType *string `json:"service_target_type,omitempty" validate:"maxLength=512,omitempty"`
	// ServiceTargetName identifies the instance name of the target service being operated on
	ServiceTargetName *string `json:"service_target_name,omitempty" validate:"maxLength=512,omitempty"`
	// Outcome of the span: success, failure, or unknown. Outcome may be one of
	// a limited set of permitted values describing the success or failure of
	// the span. It can be used for calculating error rates for outgoing requests.
	Outcome *string `json:"outcome,omitempty" validate:"enum=enumOutcome,omitempty"`
	// Duration holds duration aggregations about the dropped span.
	Duration transactionDroppedSpansDuration `json:"duration,omitempty"`
}

type transactionDroppedSpansDuration struct {
	// Count holds the number of times the dropped span happened.
	Count *int `json:"count,omitempty" validate:"min=1,omitempty"`
	// Sum holds dimensions about the dropped span's duration.
	Sum transactionDroppedSpansDurationSum `json:"sum,omitempty"`
}

type transactionDroppedSpansDurationSum struct {
	// Us represents the summation of the span duration.
	Us *int `json:"us,omitempty" validate:"min=0,omitempty"`
}

type spanLink struct {
	// SpanID holds the ID of the linked span.
	SpanID *string `json:"span_id,omitempty" validate:"required,maxLength=1024,omitempty"`

	// TraceID holds the ID of the linked span's trace.
	TraceID *string `json:"trace_id,omitempty" validate:"required,maxLength=1024,omitempty"`
}
