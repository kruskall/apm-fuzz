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

package rumv3

import (
	"net/http"
	"time"
	"encoding/json"

)

var (
	patternAlphaNumericExt = `^[a-zA-Z0-9 _-]+$`

	enumOutcome = []string{"success", "failure", "unknown"}
)

// entry points

// errorRoot requires an error event to be present
type ErrorRoot struct {
	Error errorEvent `json:"e,omitempty" validate:"required,omitempty"`
}

// metadatatRoot requires a metadata event to be present
type MetadataRoot struct {
	Metadata metadata `json:"m,omitempty" validate:"required,omitempty"`
}

// transactionRoot requires a transaction event to be present
type TransactionRoot struct {
	Transaction transaction `json:"x,omitempty" validate:"required,omitempty"`
}

// other structs

type context struct {
	// Custom can contain additional metadata to be stored with the event.
	// The format is unspecified and can be deeply nested objects.
	// The information will not be indexed or searchable in Elasticsearch.
	Custom map[string]any `json:"cu,omitempty"`
	// Tags are a flat mapping of user-defined tags. Allowed value types are
	// string, boolean and number values. Tags are indexed and searchable.
	Tags map[string]any `json:"g,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Service related information can be sent per event. Information provided
	// here will override the more generic information retrieved from metadata,
	// missing service fields will be retrieved from the metadata information.
	Service contextService `json:"se,omitempty"`
	// User holds information about the correlated user for this event. If
	// user data are provided here, all user related information from metadata
	// is ignored, otherwise the metadata's user information will be stored
	// with the event.
	User user `json:"u,omitempty"`
	// Request describes the HTTP request information in case the event was
	// created as a result of an HTTP request.
	Request contextRequest `json:"q,omitempty"`
	// Page holds information related to the current page and page referers.
	// It is only sent from RUM agents.
	Page contextPage `json:"p,omitempty"`
	// Response describes the HTTP response information in case the event was
	// created as a result of an HTTP request.
	Response contextResponse `json:"r,omitempty"`
}

type contextPage struct {
	// Referer holds the URL of the page that 'linked' to the current page.
	Referer *string `json:"rf,omitempty"`
	// URL of the current page
	URL *string `json:"url,omitempty"`
}

type contextRequest struct {
	// Env holds environment variable information passed to the monitored service.
	Env map[string]any `json:"en,omitempty"`
	// Headers includes any HTTP headers sent by the requester. Cookies will
	// be taken by headers if supplied.
	Headers *http.Header `json:"he,omitempty"`
	// HTTPVersion holds information about the used HTTP version.
	HTTPVersion *string `json:"hve,omitempty" validate:"maxLength=1024,omitempty"`
	// Method holds information about the method of the HTTP request.
	Method *string `json:"mt,omitempty" validate:"required,maxLength=1024,omitempty"`
}

type contextResponse struct {
	// Headers holds the http headers sent in the http response.
	Headers *http.Header `json:"he,omitempty"`
	// DecodedBodySize holds the size of the decoded payload.
	DecodedBodySize *int `json:"dbs,omitempty"`
	// EncodedBodySize holds the size of the encoded payload.
	EncodedBodySize *int `json:"ebs,omitempty"`
	// StatusCode sent in the http response.
	StatusCode *int `json:"sc,omitempty"`
	// TransferSize holds the total size of the payload.
	TransferSize *int `json:"ts,omitempty"`
}

type contextService struct {
	// Agent holds information about the APM agent capturing the event.
	Agent contextServiceAgent `json:"a,omitempty"`
	// Environment in which the monitored service is running,
	// e.g. `production` or `staging`.
	Environment *string `json:"en,omitempty" validate:"maxLength=1024,omitempty"`
	// Framework holds information about the framework used in the
	// monitored service.
	Framework contextServiceFramework `json:"fw,omitempty"`
	// Language holds information about the programming language of the
	// monitored service.
	Language contextServiceLanguage `json:"la,omitempty"`
	// Name of the monitored service.
	Name *string `json:"n,omitempty" validate:"maxLength=1024,pattern=patternAlphaNumericExt,omitempty"`
	// Runtime holds information about the language runtime running the
	// monitored service
	Runtime contextServiceRuntime `json:"ru,omitempty"`
	// Version of the monitored service.
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceAgent struct {
	// Name of the APM agent capturing information.
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the APM agent capturing information.
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceFramework struct {
	// Name of the used framework
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the used framework
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceLanguage struct {
	// Name of the used programming language
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the used programming language
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type contextServiceRuntime struct {
	// Name of the language runtime
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the language runtime
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type errorEvent struct {
	// _ struct{} // removed `validate:"requiredAnyOf=ex;log,omitempty"`
	// Timestamp holds the recorded time of the event, UTC based and formatted
	// as microseconds since Unix epoch.
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Log holds additional information added when the error is logged.
	Log errorLog `json:"log,omitempty"`
	// Culprit identifies the function call which was the primary perpetrator
	// of this event.
	Culprit *string `json:"cl,omitempty" validate:"maxLength=1024,omitempty"`
	// ID holds the hex encoded 128 random bits ID of the event.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// ParentID holds the hex encoded 64 random bits ID of the parent
	// transaction or span.
	ParentID *string `json:"pid,omitempty" validate:"requiredIfAny=xid;tid,maxLength=1024,omitempty"`
	// TraceID holds the hex encoded 128 random bits ID of the correlated trace.
	TraceID *string `json:"tid,omitempty" validate:"requiredIfAny=xid;pid,maxLength=1024,omitempty"`
	// TransactionID holds the hex encoded 64 random bits ID of the correlated
	// transaction.
	TransactionID *string `json:"xid,omitempty" validate:"maxLength=1024,omitempty"`
	// Exception holds information about the original error.
	// The information is language specific.
	Exception errorException `json:"ex,omitempty"`
	// Transaction holds information about the correlated transaction.
	Transaction errorTransactionRef `json:"x,omitempty"`
	// Context holds arbitrary contextual information for the event.
	Context context `json:"c,omitempty"`
}

type errorException struct {
	// _ struct{} // removed `validate:"requiredAnyOf=mg;t,omitempty"`
	// Attributes of the exception.
	Attributes map[string]any `json:"at,omitempty"`
	// Code that is set when the error happened, e.g. database error code.
	Code any `json:"cd,omitempty" validate:"inputTypes=string;int,maxLength=1024,omitempty"`
	// Cause can hold a collection of error exceptions representing chained
	// exceptions. The chain starts with the outermost exception, followed
	// by its cause, and so on.
	Cause []errorException `json:"ca,omitempty"`
	// Message contains the originally captured error message.
	Message *string `json:"mg,omitempty"`
	// Module describes the exception type's module namespace.
	Module *string `json:"mo,omitempty" validate:"maxLength=1024,omitempty"`
	// Stacktrace information of the captured exception.
	Stacktrace []stacktraceFrame `json:"st,omitempty"`
	// Type of the exception.
	Type *string `json:"t,omitempty" validate:"maxLength=1024,omitempty"`
	// Handled indicates whether the error was caught in the code or not.
	Handled *bool `json:"hd,omitempty"`
}

type errorLog struct {
	// Level represents the severity of the recorded log.
	Level *string `json:"lv,omitempty" validate:"maxLength=1024,omitempty"`
	// LoggerName holds the name of the used logger instance.
	LoggerName *string `json:"ln,omitempty" validate:"maxLength=1024,omitempty"`
	// Message of the logged error. In case a parameterized message is captured,
	// Message should contain the same information, but with any placeholders
	// being replaced.
	Message *string `json:"mg,omitempty" validate:"required,omitempty"`
	// ParamMessage should contain the same information as Message, but with
	// placeholders where parameters were logged, e.g. 'error connecting to %s'.
	// The string is not interpreted, allowing differnt placeholders per client
	// languange. The information might be used to group errors together.
	ParamMessage *string `json:"pmg,omitempty" validate:"maxLength=1024,omitempty"`
	// Stacktrace information of the captured error.
	Stacktrace []stacktraceFrame `json:"st,omitempty"`
}

type errorTransactionRef struct {
	// Name is the generic designation of a transaction in the scope of a
	// single service, eg: 'GET /users/:id'.
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Type expresses the correlated transaction's type as keyword that has
	// specific relevance within the service's domain,
	// eg: 'request', 'backgroundjob'.
	Type *string `json:"t,omitempty" validate:"maxLength=1024,omitempty"`
	// Sampled indicates whether or not the full information for a transaction
	// is captured. If a transaction is unsampled no spans and less context
	// information will be reported.
	Sampled *bool `json:"sm,omitempty"`
}

type metadata struct {
	// Labels are a flat mapping of user-defined tags. Allowed value types are
	// string, boolean and number values. Labels are indexed and searchable.
	Labels map[string]any `json:"l,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Service metadata about the monitored service.
	Service metadataService `json:"se,omitempty" validate:"required,omitempty"`
	// User metadata, which can be overwritten on a per event basis.
	User user `json:"u,omitempty"`
	// Network holds information about the network over which the
	// monitored service is communicating.
	Network network `json:"n,omitempty"`
}

type metadataService struct {
	// Agent holds information about the APM agent capturing the event.
	Agent metadataServiceAgent `json:"a,omitempty" validate:"required,omitempty"`
	// Environment in which the monitored service is running,
	// e.g. `production` or `staging`.
	Environment *string `json:"en,omitempty" validate:"maxLength=1024,omitempty"`
	// Framework holds information about the framework used in the
	// monitored service.
	Framework metadataServiceFramework `json:"fw,omitempty"`
	// Language holds information about the programming language of the
	// monitored service.
	Language metadataServiceLanguage `json:"la,omitempty"`
	// Name of the monitored service.
	Name *string `json:"n,omitempty" validate:"required,minLength=1,maxLength=1024,pattern=patternAlphaNumericExt,omitempty"`
	// Runtime holds information about the language runtime running the
	// monitored service
	Runtime metadataServiceRuntime `json:"ru,omitempty"`
	// Version of the monitored service.
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceAgent struct {
	// Name of the APM agent capturing information.
	Name *string `json:"n,omitempty" validate:"required,minLength=1,maxLength=1024,omitempty"`
	// Version of the APM agent capturing information.
	Version *string `json:"ve,omitempty" validate:"required,maxLength=1024,omitempty"`
}

type metadataServiceFramework struct {
	// Name of the used framework
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Version of the used framework
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceLanguage struct {
	// Name of the used programming language
	Name *string `json:"n,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Version of the used programming language
	Version *string `json:"ve,omitempty" validate:"maxLength=1024,omitempty"`
}

type metadataServiceRuntime struct {
	// Name of the language runtime
	Name *string `json:"n,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Name of the language runtime
	Version *string `json:"ve,omitempty" validate:"required,maxLength=1024,omitempty"`
}

type network struct {
	Connection networkConnection `json:"c,omitempty"`
}

type networkConnection struct {
	Type *string `json:"t,omitempty" validate:"maxLength=1024,omitempty"`
}

type transactionMetricset struct {
	// Span holds selected information about the correlated transaction.
	Span metricsetSpanRef `json:"y,omitempty"`
	// Samples hold application metrics collected from the agent.
	Samples transactionMetricsetSamples `json:"sa,omitempty" validate:"required,omitempty"`
}

type transactionMetricsetSamples struct {
	// SpanSelfTimeCount holds the count of the related spans' self_time.
	SpanSelfTimeCount metricsetSampleValue `json:"ysc,omitempty"`
	// SpanSelfTimeSum holds the sum of the related spans' self_time.
	SpanSelfTimeSum metricsetSampleValue `json:"yss,omitempty"`
}

type metricsetSampleValue struct {
	// Value holds the value of a single metric sample.
	Value *float64 `json:"v,omitempty" validate:"required,omitempty"`
}

type metricsetSpanRef struct {
	// Subtype is a further sub-division of the type (e.g. postgresql, elasticsearch)
	Subtype *string `json:"su,omitempty" validate:"maxLength=1024,omitempty"`
	// Type expresses the correlated span's type as keyword that has specific
	// relevance within the service's domain, eg: 'request', 'backgroundjob'.
	Type *string `json:"t,omitempty" validate:"maxLength=1024,omitempty"`
}

type span struct {
	// Name is the generic designation of a span in the scope of a transaction.
	Name *string `json:"n,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Stacktrace connected to this span event.
	Stacktrace []stacktraceFrame `json:"st,omitempty"`
	// Type holds the span's type, and can have specific keywords
	// within the service's domain (eg: 'request', 'backgroundjob', etc)
	Type *string `json:"t,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Subtype is a further sub-division of the type (e.g. postgresql, elasticsearch)
	Subtype *string `json:"su,omitempty" validate:"maxLength=1024,omitempty"`
	// Action holds the specific kind of event within the sub-type represented
	// by the span (e.g. query, connect)
	Action *string `json:"ac,omitempty" validate:"maxLength=1024,omitempty"`
	// ID holds the hex encoded 64 random bits ID of the event.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Outcome of the span: success, failure, or unknown. Outcome may be one of
	// a limited set of permitted values describing the success or failure of
	// the span. It can be used for calculating error rates for outgoing requests.
	Outcome *string `json:"o,omitempty" validate:"enum=enumOutcome,omitempty"`
	// Context holds arbitrary contextual information for the event.
	Context spanContext `json:"c,omitempty"`
	// ParentIndex is the index of the parent span in the list. Absent when
	// the parent is a transaction.
	ParentIndex *int `json:"pi,omitempty"`
	// SampleRate applied to the monitored service at the time where this span
	// was recorded.
	SampleRate *float64 `json:"sr,omitempty"`
	// Start is the offset relative to the transaction's timestamp identifying
	// the start of the span, in milliseconds.
	Start *float64 `json:"s,omitempty" validate:"required,omitempty"`
	// Duration of the span in milliseconds
	Duration *float64 `json:"d,omitempty" validate:"required,min=0,omitempty"`
	// Sync indicates whether the span was executed synchronously or asynchronously.
	Sync *bool `json:"sy,omitempty"`
}

type spanContext struct {
	// Tags are a flat mapping of user-defined tags. Allowed value types are
	// string, boolean and number values. Tags are indexed and searchable.
	Tags map[string]any `json:"g,omitempty" validate:"inputTypesVals=string;bool;number,maxLengthVals=1024,omitempty"`
	// Service related information can be sent per span. Information provided
	// here will override the more generic information retrieved from metadata,
	// missing service fields will be retrieved from the metadata information.
	Service spanContextService `json:"se,omitempty"`
	// Destination contains contextual data about the destination of spans
	Destination spanContextDestination `json:"dt,omitempty"`
	// HTTP contains contextual information when the span concerns an HTTP request.
	HTTP spanContextHTTP `json:"h,omitempty"`
}

type spanContextDestination struct {
	// Service describes the destination service
	Service spanContextDestinationService `json:"se,omitempty"`
	// Address is the destination network address:
	// hostname (e.g. 'localhost'),
	// FQDN (e.g. 'elastic.co'),
	// IPv4 (e.g. '127.0.0.1')
	// IPv6 (e.g. '::1')
	Address *string `json:"ad,omitempty" validate:"maxLength=1024,omitempty"`
	// Port is the destination network port (e.g. 443)
	Port *int `json:"po,omitempty"`
}

type spanContextDestinationService struct {
	// Name is the identifier for the destination service,
	// e.g. 'http://elastic.co', 'elasticsearch', 'rabbitmq'
	// DEPRECATED: this field will be removed in a future release
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Resource identifies the destination service resource being operated on
	// e.g. 'http://elastic.co:80', 'elasticsearch', 'rabbitmq/queue_name'
	// DEPRECATED: this field will be removed in a future release
	Resource *string `json:"rc,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Type of the destination service, e.g. db, elasticsearch. Should
	// typically be the same as span.type.
	// DEPRECATED: this field will be removed in a future release
	Type *string `json:"t,omitempty" validate:"maxLength=1024,omitempty"`
}

type spanContextHTTP struct {
	// Method holds information about the method of the HTTP request.
	Method *string `json:"mt,omitempty" validate:"maxLength=1024,omitempty"`
	// URL is the raw url of the correlating HTTP request.
	URL *string `json:"url,omitempty"`
	// Response describes the HTTP response information in case the event was
	// created as a result of an HTTP request.
	Response spanContextHTTPResponse `json:"r,omitempty"`
	// Deprecated: Use Response.StatusCode instead.
	// StatusCode sent in the http response.
	StatusCode *int `json:"sc,omitempty"`
}

type spanContextHTTPResponse struct {
	// DecodedBodySize holds the size of the decoded payload.
	DecodedBodySize *int `json:"dbs,omitempty"`
	// EncodedBodySize holds the size of the encoded payload.
	EncodedBodySize *int `json:"ebs,omitempty"`
	// TransferSize holds the total size of the payload.
	TransferSize *int `json:"ts,omitempty"`
}

type spanContextService struct {
	// Agent holds information about the APM agent capturing the event.
	Agent contextServiceAgent `json:"a,omitempty"`
	// Name of the monitored service.
	Name *string `json:"n,omitempty" validate:"maxLength=1024,pattern=patternAlphaNumericExt,omitempty"`
}

type stacktraceFrame struct {
	// AbsPath is the absolute path of the frame's file.
	AbsPath *string `json:"ap,omitempty"`
	// Classname of the frame.
	Classname *string `json:"cn,omitempty"`
	// ContextLine is the line from the frame's file.
	ContextLine *string `json:"cli,omitempty"`
	// Filename is the relative name of the frame's file.
	Filename *string `json:"f,omitempty" validate:"required,omitempty"`
	// Function represented by the frame.
	Function *string `json:"fn,omitempty"`
	// Module to which the frame belongs to.
	Module *string `json:"mo,omitempty"`
	// PostContext is a slice of code lines immediately before the line
	// from the frame's file.
	PostContext []string `json:"poc,omitempty"`
	// PreContext is a slice of code lines immediately after the line
	// from the frame's file.
	PreContext []string `json:"prc,omitempty"`
	// ColumnNumber of the frame.
	ColumnNumber *int `json:"co,omitempty"`
	// LineNumber of the frame.
	LineNumber *int `json:"li,omitempty"`
}

type transaction struct {
	// Marks capture the timing of a significant event during the lifetime of
	// a transaction. Marks are organized into groups and can be set by the
	// user or the agent. Marks are only reported by RUM agents.
	Marks transactionMarks `json:"k,omitempty"`
	// TraceID holds the hex encoded 128 random bits ID of the correlated trace.
	TraceID *string `json:"tid,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Type expresses the transaction's type as keyword that has specific
	// relevance within the service's domain, eg: 'request', 'backgroundjob'.
	Type *string `json:"t,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Spans is a collection of spans related to this transaction.
	Spans []span `json:"y,omitempty"`
	// Metricsets is a collection metrics related to this transaction.
	Metricsets []transactionMetricset `json:"me,omitempty"`
	// Result of the transaction. For HTTP-related transactions, this should
	// be the status code formatted like 'HTTP 2xx'.
	Result *string `json:"rt,omitempty" validate:"maxLength=1024,omitempty"`
	// ID holds the hex encoded 64 random bits ID of the event.
	ID *string `json:"id,omitempty" validate:"required,maxLength=1024,omitempty"`
	// Name is the generic designation of a transaction in the scope of a
	// single service, eg: 'GET /users/:id'.
	Name *string `json:"n,omitempty" validate:"maxLength=1024,omitempty"`
	// Outcome of the transaction with a limited set of permitted values,
	// describing the success or failure of the transaction from the service's
	// perspective. It is used for calculating error rates for incoming requests.
	// Permitted values: success, failure, unknown.
	Outcome *string `json:"o,omitempty" validate:"enum=enumOutcome,omitempty"`
	// ParentID holds the hex encoded 64 random bits ID of the parent
	// transaction or span.
	ParentID *string `json:"pid,omitempty" validate:"maxLength=1024,omitempty"`
	// Session holds optional transaction session information for RUM.
	Session transactionSession `json:"ses,omitempty"`
	// Context holds arbitrary contextual information for the event.
	Context context `json:"c,omitempty"`
	// UserExperience holds metrics for measuring real user experience.
	// This information is only sent by RUM agents.
	UserExperience transactionUserExperience `json:"exp,omitempty"`
	// SpanCount counts correlated spans.
	SpanCount transactionSpanCount `json:"yc,omitempty" validate:"required,omitempty"`
	// SampleRate applied to the monitored service at the time where this transaction
	// was recorded. Allowed values are [0..1]. A SampleRate <1 indicates that
	// not all spans are recorded.
	SampleRate *float64 `json:"sr,omitempty"`
	// Duration how long the transaction took to complete, in milliseconds
	// with 3 decimal points.
	Duration *float64 `json:"d,omitempty" validate:"required,min=0,omitempty"`
	// Sampled indicates whether or not the full information for a transaction
	// is captured. If a transaction is unsampled no spans and less context
	// information will be reported.
	Sampled *bool `json:"sm,omitempty"`
}

type transactionSession struct {
	// ID holds a session ID for grouping a set of related transactions.
	ID *string `json:"id,omitempty" validate:"required,omitempty"`

	// Sequence holds an optional sequence number for a transaction within
	// a session. It is not meaningful to compare sequences across two
	// different sessions.
	Sequence *int `json:"seq,omitempty" validate:"min=1,omitempty"`
}

type transactionMarks struct {
	Events map[string]transactionMarkEvents `json:"-,omitempty"`
}

var markEventsLongNames = map[string]string{
	"a":  "agent",
	"nt": "navigationTiming",
}

func (m *transactionMarks) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &m.Events); err != nil {
		return err
	}
	for name, val := range m.Events {
		nameLong, ok := markEventsLongNames[name]
		if !ok {
			// there is no long name defined for this event
			continue
		}
		delete(m.Events, name)
		m.Events[nameLong] = val
	}
	return nil
}

type transactionMarkEvents struct {
	Measurements map[string]float64 `json:"-,omitempty"`
}

func (m *transactionMarkEvents) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &m.Measurements); err != nil {
		return err
	}
	for name, val := range m.Measurements {
		nameLong, ok := markMeasurementsLongNames[name]
		if !ok {
			// there is no long name defined for this measurement
			continue
		}
		delete(m.Measurements, name)
		m.Measurements[nameLong] = val
	}
	return nil
}

var markMeasurementsLongNames = map[string]string{
	"ce": "connectEnd",
	"cs": "connectStart",
	"dc": "domComplete",
	"de": "domContentLoadedEventEnd",
	"di": "domInteractive",
	"dl": "domLoading",
	"ds": "domContentLoadedEventStart",
	"ee": "loadEventEnd",
	"es": "loadEventStart",
	"fb": "timeToFirstByte",
	"fp": "firstContentfulPaint",
	"fs": "fetchStart",
	"le": "domainLookupEnd",
	"lp": "largestContentfulPaint",
	"ls": "domainLookupStart",
	"re": "responseEnd",
	"rs": "responseStart",
	"qs": "requestStart",
}

type transactionSpanCount struct {
	// Dropped is the number of correlated spans that have been dropped by
	// the APM agent recording the transaction.
	Dropped *int `json:"dd,omitempty"`
	// Started is the number of correlated spans that are recorded.
	Started *int `json:"sd,omitempty" validate:"required,omitempty"`
}

// userExperience holds real user (browser) experience metrics.
type transactionUserExperience struct {
	// CumulativeLayoutShift holds the Cumulative Layout Shift (CLS) metric value,
	// or a negative value if CLS is unknown. See https://web.dev/cls/
	CumulativeLayoutShift *float64 `json:"cls,omitempty" validate:"min=0,omitempty"`
	// FirstInputDelay holds the First Input Delay (FID) metric value,
	// or a negative value if FID is unknown. See https://web.dev/fid/
	FirstInputDelay *float64 `json:"fid,omitempty" validate:"min=0,omitempty"`
	// TotalBlockingTime holds the Total Blocking Time (TBT) metric value,
	// or a negative value if TBT is unknown. See https://web.dev/tbt/
	TotalBlockingTime *float64 `json:"tbt,omitempty" validate:"min=0,omitempty"`
	// Longtask holds longtask duration/count metrics.
	Longtask longtaskMetrics `json:"lt,omitempty"`
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
	// Domain of the user
	Domain *string `json:"ud,omitempty" validate:"maxLength=1024,omitempty"`
	// ID identifies the logged in user, e.g. can be the primary key of the user
	ID any `json:"id,omitempty" validate:"maxLength=1024,inputTypes=string;int,omitempty"`
	// Email of the user.
	Email *string `json:"em,omitempty" validate:"maxLength=1024,omitempty"`
	// Name of the user.
	Name *string `json:"un,omitempty" validate:"maxLength=1024,omitempty"`
}
