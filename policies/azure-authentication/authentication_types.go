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

	sdkauth "github.com/wso2/api-platform/sdk/ai/azureauthentication"
)

const (
	// AuthenticationTypeWorkloadIdentity exchanges the pod's AKS Workload Identity federated
	// token for an access token.
	AuthenticationTypeWorkloadIdentity = sdkauth.WorkloadIdentity

	// AuthenticationTypeManagedIdentity gets the access token for an identity assigned to the host:
	// from the Azure Instance Metadata Service (IMDS) on a VM, VM scale set or AKS node, or from the
	// host's own managed identity endpoint on App Service or Container Apps.
	AuthenticationTypeManagedIdentity = sdkauth.ManagedIdentity

	// AuthenticationTypeContainerApps gets the access token for a managed identity of the Azure
	// Container Apps app the gateway runs in, from the identity endpoint Container Apps sets in
	// IDENTITY_ENDPOINT.
	AuthenticationTypeContainerApps = sdkauth.ContainerApps

	// AuthType is the AuthContext.AuthType value recorded for workload-identity.
	AuthType = "azure-workload-identity"

	// AuthTypeManagedIdentity is the AuthContext.AuthType value recorded for managed-identity.
	AuthTypeManagedIdentity = "azure-managed-identity"

	// AuthTypeContainerApps is the AuthContext.AuthType value recorded for container-apps.
	AuthTypeContainerApps = "azure-container-apps"
)

// authenticationKind is what the policy records and checks for an authenticationType; sdk/ai
// builds and runs its credential.
type authenticationKind struct {
	name     string // the authenticationType value
	authType string // AuthContext.AuthType

	// usesTenant: the identity is named by a tenant and a client ID, which default to
	// AZURE_TENANT_ID and AZURE_CLIENT_ID. Otherwise it is the host's, named by its client ID.
	usesTenant bool
}

// authenticationKinds are the supported authenticationTypes, in the order sdk/ai lists them.
var authenticationKinds = []*authenticationKind{
	{name: AuthenticationTypeWorkloadIdentity, authType: AuthType, usesTenant: true},
	{name: AuthenticationTypeManagedIdentity, authType: AuthTypeManagedIdentity},
	{name: AuthenticationTypeContainerApps, authType: AuthTypeContainerApps},
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
