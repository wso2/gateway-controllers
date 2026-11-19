/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package azureauthentication

import (
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

const (
	// AuthenticationTypeWorkloadIdentity exchanges the pod's AKS Workload Identity federated
	// token for an access token.
	AuthenticationTypeWorkloadIdentity = "workload-identity"

	// AuthenticationTypeManagedIdentity gets the access token for an identity assigned to the host:
	// from the Azure Instance Metadata Service (IMDS) on a VM, VM scale set or AKS node, or from the
	// host's own managed identity endpoint on App Service, Container Apps or Azure Arc.
	AuthenticationTypeManagedIdentity = "managed-identity"

	// AuthenticationTypeContainerApps gets the access token for a managed identity of the Azure
	// Container Apps app the gateway runs in, from the identity endpoint Container Apps sets in
	// IDENTITY_ENDPOINT.
	AuthenticationTypeContainerApps = "container-apps"

	// AuthType is the AuthContext.AuthType value recorded for workload-identity.
	AuthType = "azure-workload-identity"

	// AuthTypeManagedIdentity is the AuthContext.AuthType value recorded for managed-identity.
	AuthTypeManagedIdentity = "azure-managed-identity"

	// AuthTypeContainerApps is the AuthContext.AuthType value recorded for container-apps.
	AuthTypeContainerApps = "azure-container-apps"
)

// authenticationKind describes an authenticationType: how its credential is built, how its
// identity is named, and how its token service behaves.
type authenticationKind struct {
	name     string // the authenticationType value
	authType string // AuthContext.AuthType
	service  string // the token service, as fault reasons and the failure log name it

	// unavailable begins GetPolicy's error when the credential can't be built.
	unavailable string

	// usesTenant: the identity is named by a tenant and a client ID, which default to
	// AZURE_TENANT_ID and AZURE_CLIENT_ID, so tenantId is a parameter and the tenant is logged and
	// recorded. Otherwise the identity is the host's, named by clientId or the host's default.
	usesTenant bool

	// oneFetchAtATime: the SDK fetches one token at a time per credential, behind a lock that
	// doesn't watch the caller's context, so all of a credential's scopes share one admission slot.
	oneFetchAtATime bool

	// imds: the token service may be IMDS, which answers 404 and 410 while it starts or updates,
	// and whose refusal of the host's default identity the SDK passes on without the response.
	imds bool

	newCredential func(identity) (azcore.TokenCredential, error)
}

// authenticationKinds are the supported authenticationTypes, in the order the docs list them.
var authenticationKinds = []*authenticationKind{
	{
		name:     AuthenticationTypeWorkloadIdentity,
		authType: AuthType,
		service:  "Microsoft Entra ID",
		unavailable: "workload identity is not available (the AKS Workload Identity webhook normally sets " +
			"AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_FEDERATED_TOKEN_FILE)",
		usesTenant:      true,
		oneFetchAtATime: true,
		newCredential:   newWorkloadIdentityCredential,
	},
	{
		// A managed identity token comes from IMDS on a VM or AKS node, or from the host's own
		// endpoint on App Service, Container Apps or Arc.
		name:          AuthenticationTypeManagedIdentity,
		authType:      AuthTypeManagedIdentity,
		service:       "the managed identity endpoint",
		unavailable:   "managed identity is not available",
		imds:          true,
		newCredential: newManagedIdentityCredential,
	},
	{
		name:     AuthenticationTypeContainerApps,
		authType: AuthTypeContainerApps,
		service:  "the Container Apps identity endpoint",
		unavailable: "Container Apps managed identity is not available (Container Apps sets " +
			"IDENTITY_ENDPOINT and IDENTITY_HEADER when the container app has a managed identity)",
		newCredential: newContainerAppsCredential,
	},
}

// kindOf returns the authenticationType called name, or nil if there is none.
func kindOf(name string) *authenticationKind {
	for _, k := range authenticationKinds {
		if k.name == name {
			return k
		}
	}
	return nil
}

// authenticationTypeNames are the authenticationType values, quoted, for error messages.
func authenticationTypeNames() []string {
	names := make([]string, len(authenticationKinds))
	for i, k := range authenticationKinds {
		names[i] = strconv.Quote(k.name)
	}
	return names
}
