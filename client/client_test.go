/*
 *
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"fmt"
	pb "github.com/wogri/captive_portal/whitelist"
	"reflect"
	"testing"
	"time"
)

func TestBuildCommand(t *testing.T) {
	entry := &pb.WhitelistEntry{Ipv4Address: "192.168.1.1",
		ValidUntil: int64(time.Now().Unix() + 100)}
	cmd := build_command(entry)
	fmt.Printf("%v", cmd.Args)
	expected_output := []string{
		"/usr/sbin/nft",
		"add",
		"element",
		"inet",
		"filter",
		"trusted_set",
		"{",
		"192.168.1.1",
		"timeout",
		"100s",
		"}"}
	if !reflect.DeepEqual(cmd.Args, expected_output) {
		t.Errorf("Expected nft command differs: \n%v\nvs\n%v", cmd.Args,
			expected_output)
	}
}
