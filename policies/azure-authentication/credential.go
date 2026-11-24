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
	"context"
	"time"

	sdkauth "github.com/wso2/api-platform/sdk/ai/azureauthentication"
)

// tokenSource gets access tokens for one identity. *sdkauth.Credential is the real one; tests
// replace getTokenSource to fake it.
type tokenSource interface {
	Token(ctx context.Context, scope string, timeout time.Duration) (string, error)
	Service() string
}

// getTokenSource returns the gateway-wide credential for id, which every policy with the same
// identity shares. Its error says which identity is unavailable and why.
var getTokenSource = func(id sdkauth.Identity) (tokenSource, error) {
	cred, err := sdkauth.Get(id)
	if err != nil {
		return nil, err
	}
	return cred, nil
}
