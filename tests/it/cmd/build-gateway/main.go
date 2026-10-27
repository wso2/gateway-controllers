/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Command build-gateway builds the gateway image set one run of the integration suites boots,
// from the policies of this repository, and writes the variables that make the suites boot it.
//
//	go run ./cmd/build-gateway -policies-dir ../../policies -version 1.2.0 -env-file /tmp/gateway.env
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wso2/gateway-controllers/tests/it/common/gateway"
)

func main() {
	policiesDir := flag.String("policies-dir", "", "the folder that holds the policy folders")
	policies := flag.String("policies", "", "comma-separated policies to build in (default: every policy)")
	version := flag.String("version", "", "the released gateway version to build on, or latest")
	host := flag.String("host", "", "the image repository prefix of the gateway's base images")
	envFile := flag.String("env-file", "", "the file to write the NAME=value lines to")
	flag.Parse()

	if *envFile == "" {
		fmt.Fprintln(os.Stderr, "build-gateway: -env-file is required")
		os.Exit(2)
	}
	started := time.Now()
	images, err := gateway.Build(context.Background(), gateway.BuildOptions{
		PoliciesDir: *policiesDir,
		Policies:    splitList(*policies),
		Version:     *version,
		Host:        *host,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "build-gateway:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*envFile, environmentLines(images), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "build-gateway:", err)
		os.Exit(1)
	}
	fmt.Printf("gateway %s built in %.1fs: %s, %s\n", *version, time.Since(started).Seconds(), images.Controller, images.Runtime)
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func environmentLines(images gateway.Images) []byte {
	environment := images.Environment()
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&b, "%s=%s\n", key, environment[key])
	}
	return []byte(b.String())
}
