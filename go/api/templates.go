package api

import (
	"bytes"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ptrus/rofl-attestations/models"
	"github.com/ptrus/rofl-attestations/rofl"
)

const (
	notYetVerified = "Not yet verified"
	statusVerified = "verified"
)

// slugify converts a string to a URL-safe slug.
func slugify(s string) string {
	// Convert to lowercase
	s = strings.ToLower(s)
	// Replace spaces and special chars with hyphens
	reg := regexp.MustCompile(`[^a-z0-9]+`)
	s = reg.ReplaceAllString(s, "-")
	// Remove leading/trailing hyphens
	s = strings.Trim(s, "-")
	return s
}

// EnclaveIdentity holds enclave identity information.
type EnclaveIdentity struct {
	Type  string
	Value string
}

// DeploymentInfo holds deployment details for display.
type DeploymentInfo struct {
	Name     string
	Network  string
	AppID    string
	Enclaves []EnclaveIdentity
}

// DeploymentStatus holds verification status for a deployment.
type DeploymentStatus struct {
	Name            string
	Status          string // "verified", "pending", "failed"
	CommitSHA       string
	CommitSHAShort  string
	VerificationMsg string
	LastVerified    string
	EnclaveIDs      []string
}

// AppCardData holds the data for rendering an app card.
type AppCardData struct {
	ID                int64
	Name              string
	Slug              string // URL-safe slug for the app name
	Version           string
	Description       string
	GitHubURL         string
	Author            string
	License           string
	TEE               string
	Kind              string
	Repository        string
	Homepage          string
	Memory            int
	CPUs              float64
	StorageKind       string
	StorageSize       int
	Status            string // Aggregated status (mainnet preferred)
	MainnetDeployment *DeploymentStatus
	OtherDeployments  []DeploymentStatus
	Networks          []string
	NetworksStr       string
	Deployments       []DeploymentInfo
	Builder           string
	Firmware          string
	Kernel            string
	Stage2            string
	ContainerRuntime  string
	ContainerCompose  string
	RoflYAML          string
}

var appCardTemplate = `<!-- App Card: {{.Name}} -->
<div class="app-card bg-white border border-slate-200 rounded-lg p-6 shadow-sm hover:shadow-md transition-shadow h-full flex flex-col"
     data-status="{{.Status}}"
     data-tee="{{.TEE}}"
     data-networks="{{.NetworksStr}}"
     data-name="{{.Name}}"
     data-app-id="{{.ID}}"
     id="card-{{.ID}}">

    <div class="flex justify-between items-start mb-4">
        <div>
            <h3 class="text-2xl font-bold text-slate-900 mb-2">{{.Name}}</h3>
            <span class="inline-block px-3 py-1 bg-slate-100 text-slate-700 rounded-md text-sm font-semibold">{{.Version}}</span>
        </div>
        {{if eq .Status "verified"}}
        <div class="flex items-center gap-2 px-4 py-2 bg-emerald-50 border border-emerald-200 text-emerald-700 rounded-lg font-semibold text-sm">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            Verified
        </div>
        {{else if eq .Status "pending"}}
        <div class="flex items-center gap-2 px-4 py-2 bg-amber-50 border border-amber-200 text-amber-700 rounded-lg font-semibold text-sm">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            Pending
        </div>
        {{else}}
        <div class="flex items-center gap-2 px-4 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg font-semibold text-sm">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            Failed
        </div>
        {{end}}
    </div>

    <div class="flex flex-wrap gap-2 mb-4">
        <span class="px-3 py-1 bg-slate-100 text-slate-700 rounded-md text-xs font-semibold uppercase">{{.TEE}}</span>
        {{range .Networks}}
        {{if eq . "mainnet"}}
        <span class="px-3 py-1 bg-slate-100 text-slate-700 rounded-md text-xs font-medium">Mainnet</span>
        {{else}}
        <span class="px-3 py-1 bg-slate-100 text-slate-700 rounded-md text-xs font-medium">Testnet</span>
        {{end}}
        {{end}}
    </div>

    <div class="text-slate-600 mb-6 leading-relaxed" style="height: 4.5rem; overflow: hidden; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical;">
        {{if .Description}}{{.Description}}{{else}}<span class="text-slate-400 italic">No description available</span>{{end}}
    </div>

    <div class="border-t border-slate-200 pt-4 mt-auto">
        <!-- Verification Status -->
        <div class="text-sm text-slate-600 mb-3">
            {{if .MainnetDeployment}}
                {{if and (eq .MainnetDeployment.Status "verified") .MainnetDeployment.CommitSHA}}
                <div class="flex items-center gap-1.5">
                    Mainnet:
                    <span class="text-emerald-700 font-medium inline-flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                        Verified
                    </span>
                    <span class="text-slate-900 font-mono text-xs">{{.MainnetDeployment.CommitSHAShort}}</span>
                </div>
                <div class="text-xs text-slate-500 mt-1">{{.MainnetDeployment.LastVerified}}</div>
                {{else if eq .MainnetDeployment.Status "pending"}}
                <div class="flex items-center gap-1.5">
                    Mainnet:
                    <span class="text-amber-700 font-medium inline-flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        Pending
                    </span>
                </div>
                <div class="text-xs text-slate-500 mt-1">{{.MainnetDeployment.LastVerified}}</div>
                {{else}}
                <div class="flex items-center gap-1.5">
                    Mainnet:
                    <span class="text-red-700 font-medium inline-flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                        Failed
                    </span>
                    {{if .MainnetDeployment.CommitSHAShort}}
                    <span class="text-slate-900 font-mono text-xs">{{.MainnetDeployment.CommitSHAShort}}</span>
                    {{end}}
                </div>
                <div class="text-xs text-slate-500 mt-1">{{.MainnetDeployment.LastVerified}}</div>
                {{end}}
            {{else if .OtherDeployments}}
                {{$first := index .OtherDeployments 0}}
                {{if and (eq $first.Status "verified") $first.CommitSHA}}
                <div class="flex items-center gap-1.5">
                    {{if eq $first.Name "testnet"}}Testnet{{else}}{{$first.Name}}{{end}}:
                    <span class="text-emerald-700 font-medium inline-flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                        Verified
                    </span>
                    <span class="text-slate-900 font-mono text-xs">{{$first.CommitSHAShort}}</span>
                </div>
                <div class="text-xs text-slate-500 mt-1">{{$first.LastVerified}}</div>
                {{else if eq $first.Status "pending"}}
                <div class="flex items-center gap-1.5">
                    {{if eq $first.Name "testnet"}}Testnet{{else}}{{$first.Name}}{{end}}:
                    <span class="text-amber-700 font-medium inline-flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        Pending
                    </span>
                </div>
                <div class="text-xs text-slate-500 mt-1">{{$first.LastVerified}}</div>
                {{else}}
                <div class="flex items-center gap-1.5">
                    {{if eq $first.Name "testnet"}}Testnet{{else}}{{$first.Name}}{{end}}:
                    <span class="text-red-700 font-medium inline-flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                        Failed
                    </span>
                    {{if $first.CommitSHAShort}}
                    <span class="text-slate-900 font-mono text-xs">{{$first.CommitSHAShort}}</span>
                    {{end}}
                </div>
                <div class="text-xs text-slate-500 mt-1">{{$first.LastVerified}}</div>
                {{end}}
            {{else}}
            <div><span class="text-slate-500 font-medium">Not yet verified</span></div>
            {{end}}
        </div>

        <!-- Links and Button -->
        <div class="flex flex-wrap gap-3 items-center">
            {{if .Homepage}}
            <a href="{{.Homepage}}"
               target="_blank"
               onclick="event.stopPropagation()"
               class="text-blue-600 hover:text-blue-800 hover:underline text-xs font-medium flex items-center gap-1">
                <svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <span>Website</span>
                <svg class="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                </svg>
            </a>
            {{end}}
            {{if .Repository}}
            <a href="{{.Repository}}"
               target="_blank"
               onclick="event.stopPropagation()"
               class="text-blue-600 hover:text-blue-800 hover:underline text-xs font-medium flex items-center gap-1 max-w-[200px] truncate">
                <span class="truncate">{{.Repository}}</span>
                <svg class="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                </svg>
            </a>
            {{else}}
            <a href="{{.GitHubURL}}"
               target="_blank"
               onclick="event.stopPropagation()"
               class="text-blue-600 hover:text-blue-800 hover:underline text-xs font-medium flex items-center gap-1 max-w-[200px] truncate">
                <span class="truncate">{{.GitHubURL}}</span>
                <svg class="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                </svg>
            </a>
            {{end}}
            <button onclick="openModal({{.ID}}, '{{.Slug}}')"
                    class="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg font-semibold text-sm transition-colors whitespace-nowrap ml-auto">
                Show Details
            </button>
        </div>

        <!-- Enclave IDs / Status Box -->
        {{if .MainnetDeployment}}
            {{if and (eq .MainnetDeployment.Status "verified") .MainnetDeployment.EnclaveIDs}}
            <div class="bg-emerald-50 border border-emerald-200 rounded-md p-3 text-xs mt-3">
                <div class="font-semibold text-emerald-900 mb-2">Mainnet Enclave IDs:</div>
                <div class="space-y-1">
                    {{range .MainnetDeployment.EnclaveIDs}}
                    <div class="font-mono text-emerald-800 break-all text-xs">{{.}}</div>
                    {{end}}
                </div>
            </div>
            {{else}}
            <div class="bg-slate-50 border border-slate-200 rounded-md p-3 text-xs mt-3">
                {{if eq .MainnetDeployment.Status "pending"}}
                <div class="text-slate-600 text-center">Mainnet verification pending</div>
                {{else if eq .MainnetDeployment.Status "failed"}}
                <div class="text-red-800 font-semibold mb-1">Mainnet verification failed</div>
                {{if .MainnetDeployment.VerificationMsg}}
                <div class="text-slate-600 text-xs leading-relaxed line-clamp-3">{{.MainnetDeployment.VerificationMsg}}</div>
                {{end}}
                <div class="text-slate-500 text-xs mt-2 italic">See details for more information</div>
                {{end}}
            </div>
            {{end}}
        {{else}}
        <div class="bg-slate-50 border border-slate-200 rounded-md p-3 text-xs mt-3">
            {{if eq .Status "pending"}}
            <div class="text-slate-600 text-center">Verification pending</div>
            {{else if eq .Status "failed"}}
            {{$first := index .OtherDeployments 0}}
            <div class="text-red-800 font-semibold mb-1">{{if eq $first.Name "testnet"}}Testnet{{else}}{{$first.Name}}{{end}} verification failed</div>
            {{if $first.VerificationMsg}}
            <div class="text-slate-600 text-xs leading-relaxed line-clamp-3">{{$first.VerificationMsg}}</div>
            {{end}}
            <div class="text-slate-500 text-xs mt-2 italic">See details for more information</div>
            {{else}}
            <div class="text-slate-600 text-center">Not yet verified</div>
            {{end}}
        </div>
        {{end}}
    </div>
</div>

<!-- Modal Content for {{.Name}} -->
<div id="modal-content-{{.ID}}" class="hidden">
    <!-- Modal Header -->
    <div class="mb-6">
        <div class="flex justify-between items-start">
            <div>
                <h2 class="text-3xl font-bold text-slate-900 mb-2">{{.Name}}</h2>
                <div class="flex items-center gap-3">
                    <span class="inline-block px-3 py-1 bg-slate-100 text-slate-700 rounded-md text-sm font-semibold">{{.Version}}</span>
                    {{if eq .Status "verified"}}
                    <span class="inline-flex items-center gap-2 px-3 py-1 bg-emerald-50 border border-emerald-200 text-emerald-700 rounded-md text-sm font-semibold">
                        <span>✓</span> Verified
                    </span>
                    {{else if eq .Status "pending"}}
                    <span class="inline-flex items-center gap-2 px-3 py-1 bg-amber-50 border border-amber-200 text-amber-700 rounded-md text-sm font-semibold">
                        <span>⏳</span> Pending
                    </span>
                    {{else}}
                    <span class="inline-flex items-center gap-2 px-3 py-1 bg-red-50 border border-red-200 text-red-700 rounded-md text-sm font-semibold">
                        <span>✗</span> Failed
                    </span>
                    {{end}}
                </div>
            </div>
        </div>
        <p class="text-slate-600 mt-3 leading-relaxed">{{.Description}}</p>
    </div>

    <div class="space-y-4">
        <!-- Verification Details -->
            <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h4 class="text-lg font-bold text-slate-900 mb-3">Verification Details</h4>
                {{if .MainnetDeployment}}
                <div class="mb-4 pb-4 border-b border-slate-300">
                    <div class="font-semibold text-slate-900 mb-2">Mainnet</div>
                    <div class="space-y-2 text-sm">
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Status:</span>
                            <span class="text-slate-900">{{.MainnetDeployment.Status}}</span>
                        </div>
                        {{if .MainnetDeployment.CommitSHA}}
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Commit SHA:</span>
                            <span class="font-mono text-xs text-slate-700">{{.MainnetDeployment.CommitSHA}}</span>
                        </div>
                        {{end}}
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Last Verified:</span>
                            <span class="text-slate-700">{{.MainnetDeployment.LastVerified}}</span>
                        </div>
                        {{if .MainnetDeployment.VerificationMsg}}
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Message:</span>
                            <span class="text-slate-700 whitespace-pre-wrap text-xs">{{.MainnetDeployment.VerificationMsg}}</span>
                        </div>
                        {{end}}
                        {{if and (eq .MainnetDeployment.Status "verified") .MainnetDeployment.EnclaveIDs}}
                        <div class="grid grid-cols-1 gap-2 mt-2">
                            <div class="font-semibold text-emerald-900">Enclave IDs:</div>
                            <div class="space-y-1">
                                {{range .MainnetDeployment.EnclaveIDs}}
                                <div class="bg-emerald-50 border border-emerald-200 rounded px-2 py-1">
                                    <div class="font-mono text-xs text-emerald-800 break-all">{{.}}</div>
                                </div>
                                {{end}}
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
                {{range .OtherDeployments}}
                <div class="mb-4 pb-4 border-b border-slate-300 last:border-b-0 last:mb-0 last:pb-0">
                    <div class="font-semibold text-slate-900 mb-2">{{.Name}}</div>
                    <div class="space-y-2 text-sm">
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Status:</span>
                            <span class="text-slate-900">{{.Status}}</span>
                        </div>
                        {{if .CommitSHA}}
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Commit SHA:</span>
                            <div class="flex items-center gap-2">
                                <span class="font-mono text-xs text-slate-700">{{.CommitSHA}}</span>
                                <button onclick="copyToClipboard('{{.CommitSHA}}', this)"
                                        class="flex-shrink-0 p-1 hover:bg-slate-200 rounded transition-colors text-slate-600 hover:text-slate-900"
                                        title="Copy to clipboard">
                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                    </svg>
                                </button>
                            </div>
                        </div>
                        {{end}}
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Last Verified:</span>
                            <span class="text-slate-700">{{.LastVerified}}</span>
                        </div>
                        {{if .VerificationMsg}}
                        <div class="grid grid-cols-[120px_1fr] gap-2">
                            <span class="text-slate-600 font-semibold">Message:</span>
                            <span class="text-slate-700 text-xs leading-relaxed">{{.VerificationMsg}}</span>
                        </div>
                        {{end}}
                        {{if and (eq .Status "verified") .EnclaveIDs}}
                        <div class="grid grid-cols-1 gap-2 mt-2">
                            <div class="font-semibold text-emerald-900">Enclave IDs:</div>
                            <div class="space-y-1">
                                {{range .EnclaveIDs}}
                                <div class="bg-emerald-50 border border-emerald-200 rounded px-2 py-1">
                                    <div class="font-mono text-xs text-emerald-800 break-all">{{.}}</div>
                                </div>
                                {{end}}
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
                {{if and (not .MainnetDeployment) (not .OtherDeployments)}}
                <div class="text-sm text-slate-600 text-center py-4">No deployments verified yet</div>
                {{end}}
            </div>

            <!-- Application Info -->
            <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h4 class="text-lg font-bold text-slate-900 mb-3">Application Info</h4>
                <div class="space-y-2 text-sm">
                    {{if .Author}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Author:</span>
                        <span class="text-slate-700">{{.Author}}</span>
                    </div>
                    {{end}}
                    {{if .License}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">License:</span>
                        <span class="text-slate-700">{{.License}}</span>
                    </div>
                    {{end}}
                    {{if .Kind}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Kind:</span>
                        <span class="text-slate-700">{{.Kind}}</span>
                    </div>
                    {{end}}
                    {{if .Repository}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Repository:</span>
                        <a href="{{.Repository}}" target="_blank" class="text-blue-600 hover:text-blue-800 underline">{{.Repository}}</a>
                    </div>
                    {{end}}
                    {{if .Homepage}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Homepage:</span>
                        <a href="{{.Homepage}}" target="_blank" class="text-blue-600 hover:text-blue-800 underline">{{.Homepage}}</a>
                    </div>
                    {{end}}
                </div>
            </div>

            <!-- Resource Requirements -->
            {{if or .Memory .CPUs .StorageKind}}
            <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h4 class="text-lg font-bold text-slate-900 mb-3">Resource Requirements</h4>
                <div class="space-y-2 text-sm">
                    {{if .Memory}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Memory:</span>
                        <span class="text-slate-700">{{.Memory}} MB</span>
                    </div>
                    {{end}}
                    {{if .CPUs}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">CPUs:</span>
                        <span class="text-slate-700">{{.CPUs}}</span>
                    </div>
                    {{end}}
                    {{if .StorageKind}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Storage:</span>
                        <span class="text-slate-700">{{.StorageKind}} ({{.StorageSize}} MB)</span>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}

            <!-- Artifacts -->
            {{if or .Builder .Firmware .Kernel .Stage2 .ContainerRuntime}}
            <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h4 class="text-lg font-bold text-slate-900 mb-3">Runtime Artifacts</h4>
                <div class="space-y-2 text-sm">
                    {{if .Builder}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Builder:</span>
                        <span class="font-mono text-xs text-slate-700 break-all">{{.Builder}}</span>
                    </div>
                    {{end}}
                    {{if .Firmware}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Firmware:</span>
                        <span class="font-mono text-xs text-slate-700 break-all">{{.Firmware}}</span>
                    </div>
                    {{end}}
                    {{if .Kernel}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Kernel:</span>
                        <span class="font-mono text-xs text-slate-700 break-all">{{.Kernel}}</span>
                    </div>
                    {{end}}
                    {{if .Stage2}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Stage2:</span>
                        <span class="font-mono text-xs text-slate-700 break-all">{{.Stage2}}</span>
                    </div>
                    {{end}}
                    {{if .ContainerRuntime}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Runtime:</span>
                        <span class="font-mono text-xs text-slate-700 break-all">{{.ContainerRuntime}}</span>
                    </div>
                    {{end}}
                    {{if .ContainerCompose}}
                    <div class="grid grid-cols-[120px_1fr] gap-2">
                        <span class="text-slate-600 font-semibold">Compose:</span>
                        <span class="font-mono text-xs text-slate-700 break-all">{{.ContainerCompose}}</span>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}

            <!-- Deployments -->
            {{if .Deployments}}
            <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h4 class="text-lg font-bold text-slate-900 mb-3">Deployments</h4>
                <div class="space-y-3 text-sm">
                    {{range .Deployments}}
                    <div class="bg-white border border-slate-300 rounded-md p-3">
                        <div class="font-semibold text-slate-900 mb-2">{{.Name}}</div>
                        <div class="space-y-1">
                            {{if .Network}}
                            <div class="grid grid-cols-[80px_1fr] gap-2">
                                <span class="text-slate-600">Network:</span>
                                <span class="text-slate-700">{{.Network}}</span>
                            </div>
                            {{end}}
                            {{if .AppID}}
                            <div class="grid grid-cols-[80px_1fr] gap-2">
                                <span class="text-slate-600">App ID:</span>
                                <a href="https://explorer.oasis.io/{{.Network}}/sapphire/rofl/app/{{.AppID}}"
                                   target="_blank"
                                   rel="noopener noreferrer"
                                   class="font-mono text-xs text-blue-600 hover:text-blue-800 hover:underline break-all">
                                    {{.AppID}} ↗
                                </a>
                            </div>
                            {{end}}
                            {{if .Enclaves}}
                            <div class="mt-2 pt-2 border-t border-slate-200">
                                <div class="text-slate-600 font-semibold mb-1">Enclave Identities:</div>
                                <div class="space-y-1">
                                    {{range .Enclaves}}
                                    <div class="bg-slate-50 rounded px-2 py-1">
                                        <div class="text-xs text-slate-600">{{.Type}}</div>
                                        <div class="font-mono text-xs text-slate-700 break-all">{{.Value}}</div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}

            <!-- Raw rofl.yaml -->
            {{if .RoflYAML}}
            <div class="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <div class="flex justify-between items-center mb-3">
                    <h4 class="text-lg font-bold text-slate-900">rofl.yaml</h4>
                    <button onclick="toggleYaml(event, {{.ID}})" class="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white rounded-md text-xs font-semibold transition-colors">
                        Show rofl.yaml
                    </button>
                </div>
                <div id="yaml-{{.ID}}" class="hidden">
                    <pre class="bg-slate-900 text-slate-100 rounded-md p-4 text-xs overflow-x-auto"><code>{{.RoflYAML}}</code></pre>
                </div>
            </div>
            {{end}}
        </div>
    </div>
</div>
`

func (s *Server) renderAppCard(app *models.App, deployments []*models.Deployment) (string, error) {
	// Parse rofl.yaml if available.
	var manifest *rofl.Manifest
	if app.RoflYAML.Valid && app.RoflYAML.String != "" {
		var err error
		manifest, err = rofl.Parse([]byte(app.RoflYAML.String))
		if err != nil {
			return "", fmt.Errorf("failed to parse rofl.yaml: %w", err)
		}
	} else {
		// Empty manifest for apps without rofl.yaml yet.
		manifest = &rofl.Manifest{}
	}

	// Extract networks from deployments.
	// Only support mainnet and testnet - hardcode them.
	networks := []string{}
	networkSet := make(map[string]bool)

	// Check if app has mainnet or testnet deployments
	for _, dep := range deployments {
		if dep.DeploymentName == "mainnet" && !networkSet["mainnet"] {
			networks = append(networks, "mainnet")
			networkSet["mainnet"] = true
		}
		if dep.DeploymentName == "testnet" && !networkSet["testnet"] {
			networks = append(networks, "testnet")
			networkSet["testnet"] = true
		}
	}

	// Process deployments from database
	var mainnetDeployment *DeploymentStatus
	var otherDeployments []DeploymentStatus

	for _, dep := range deployments {
		// Get enclave IDs for this deployment from rofl.yaml
		var enclaveIDs []string
		if manifestDep, ok := manifest.Deployments[dep.DeploymentName]; ok && manifestDep != nil {
			// Policy.Enclaves might be nil or empty if not specified in rofl.yaml
			if manifestDep.Policy.Enclaves != nil {
				for _, enc := range manifestDep.Policy.Enclaves {
					if enc != "" {
						enclaveIDs = append(enclaveIDs, enc)
					}
				}
			}
		}

		deploymentStatus := DeploymentStatus{
			Name:            dep.DeploymentName,
			Status:          string(dep.Status),
			CommitSHA:       dep.CommitSHA.String,
			CommitSHAShort:  shortSHA(dep.CommitSHA.String),
			VerificationMsg: dep.VerificationMsg.String,
			LastVerified:    formatTime(dep.LastVerified),
			EnclaveIDs:      enclaveIDs,
		}

		// Mainnet takes priority
		if dep.DeploymentName == "mainnet" {
			mainnetDeployment = &deploymentStatus
		} else {
			otherDeployments = append(otherDeployments, deploymentStatus)
		}
	}

	// Determine aggregated status: mainnet preferred, otherwise first verified, otherwise first deployment.
	// Default to "pending" which covers: (1) apps with no deployments yet, (2) rofl.yaml not fetched,
	// or (3) no deployments configured in rofl.yaml (will remain pending indefinitely).
	aggregatedStatus := "pending"
	if mainnetDeployment != nil {
		aggregatedStatus = mainnetDeployment.Status
	} else if len(otherDeployments) > 0 {
		// Check if any other deployment is verified
		for _, dep := range otherDeployments {
			if dep.Status == statusVerified {
				aggregatedStatus = statusVerified
				break
			}
		}
		// If none verified, use status of first deployment
		if aggregatedStatus != statusVerified {
			aggregatedStatus = otherDeployments[0].Status
		}
	}
	// Note: If no deployments exist in database and rofl.yaml has no deployments,
	// status remains "pending". This is intentional - UI shows "⏳ Pending" which is
	// semantically acceptable for "not yet verified" or "not configured".

	// Extract all deployments info for rofl.yaml display.
	var deploymentInfos []DeploymentInfo
	for name, deployment := range manifest.Deployments {
		if deployment == nil {
			continue
		}
		var enclaves []EnclaveIdentity
		// Policy.Enclaves might be nil or empty if not specified in rofl.yaml
		if deployment.Policy.Enclaves != nil {
			for _, enc := range deployment.Policy.Enclaves {
				if enc != "" {
					enclaves = append(enclaves, EnclaveIdentity{
						Type:  "Enclave ID",
						Value: enc,
					})
				}
			}
		}
		deploymentInfos = append(deploymentInfos, DeploymentInfo{
			Name:     name,
			Network:  deployment.Network,
			AppID:    deployment.AppID,
			Enclaves: enclaves,
		})
	}

	// Get raw rofl.yaml content.
	roflYAML := ""
	if app.RoflYAML.Valid {
		roflYAML = app.RoflYAML.String
	}

	data := AppCardData{
		ID:                app.ID,
		Name:              manifest.Name,
		Slug:              slugify(manifest.Name),
		Version:           manifest.Version,
		Description:       manifest.Description,
		GitHubURL:         app.GitHubURL,
		Author:            manifest.Author,
		License:           manifest.License,
		TEE:               manifest.TEE,
		Kind:              manifest.Kind,
		Repository:        manifest.Repository,
		Homepage:          manifest.Homepage,
		Memory:            manifest.Resources.Memory,
		CPUs:              manifest.Resources.CPUs,
		StorageKind:       manifest.Resources.Storage.Kind,
		StorageSize:       manifest.Resources.Storage.Size,
		Status:            aggregatedStatus,
		MainnetDeployment: mainnetDeployment,
		OtherDeployments:  otherDeployments,
		Networks:          networks,
		NetworksStr:       joinNetworks(networks),
		Deployments:       deploymentInfos,
		Builder:           manifest.Artifacts.Builder,
		Firmware:          manifest.Artifacts.Firmware,
		Kernel:            manifest.Artifacts.Kernel,
		Stage2:            manifest.Artifacts.Stage2,
		ContainerRuntime:  manifest.Artifacts.Container.Runtime,
		ContainerCompose:  manifest.Artifacts.Container.Compose,
		RoflYAML:          roflYAML,
	}

	// Use default values if rofl.yaml is not available.
	if data.Name == "" {
		data.Name = "Unknown App"
		data.Description = "Verification pending..."
	}

	// Render template using pre-parsed template.
	var buf bytes.Buffer
	if err := s.cardTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func formatTime(t interface{}) string {
	switch v := t.(type) {
	case time.Time:
		return timeAgo(v)
	case sql.NullTime:
		if v.Valid {
			return timeAgo(v.Time)
		}
		return notYetVerified
	default:
		return notYetVerified
	}
}

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return notYetVerified
	}

	diff := time.Since(t)

	if diff < time.Minute {
		return "just now"
	}
	if diff < time.Hour {
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	}
	if diff < 24*time.Hour {
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}

	days := int(diff.Hours() / 24)
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

func joinNetworks(networks []string) string {
	result := ""
	for i, n := range networks {
		if i > 0 {
			result += ","
		}
		result += n
	}
	return result
}
