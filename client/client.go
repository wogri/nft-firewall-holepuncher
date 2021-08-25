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
	"flag"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/wogri/captive_portal/proto"
)

var (
	server_address = flag.String(
		"server_address", "localhost:8080", "Server Address (Dns + Port)")
	nft_table_name = flag.String(
		"nft_table_name", "filter", "NFT Table name that contains the named sets")
	nft_ipv4_set_name = flag.String(
		"nft_ipv4_set_name", "trusted_set",
		"NFT set name name that receives ipv6 addresses from this binary")
	nft_ipv6_set_name = flag.String(
		"nft_ipv6_set_name", "trusted6_set",
		"NFT set name name that receives ipv6 addresses from this binary")
	nft_path = flag.String(
		"nft_path", "/usr/sbin/nft", "Path to the nft binary")
	firewall_mode = flag.String(
		"firewall_mode", "nft", "<nft|iptables|dummy> - Firewall mode. Iptables "+
			"is not implemented, dummy does work with no underlying firewall "+
			"software as well.")
)

func build_command(entry *pb.WhitelistEntry) *exec.Cmd {
	timeout := entry.ValidUntil - int64(time.Now().Unix())
	// There's a chance that by when we receive the data it is not valid
	// anymore. Ignore these fields.
	if timeout <= 0 {
		return nil
	}
	timeout_in_sec := strconv.FormatInt(timeout, 10) + "s"
	var set_name string
	var addr string
	if temp_addr := entry.GetIpv4Address(); temp_addr != "" {
		set_name = *nft_ipv4_set_name
		addr = temp_addr
	}
	if temp_addr := entry.GetIpv6Address(); temp_addr != "" {
		set_name = *nft_ipv6_set_name
		addr = temp_addr
	}
	return exec.Command(*nft_path, "add", "element", "inet",
		*nft_table_name, set_name, "{", addr, "timeout",
		timeout_in_sec, "}")

}

func send_whitelist_to_nftables(whitelist []*pb.WhitelistEntry) {
	for _, entry := range whitelist {
		cmd := build_command(entry)
		if cmd == nil {
			continue
		}
		log.Printf("Executing: # %v", strings.Join(cmd.Args, " "))

		if *firewall_mode == "nft" {
			stdoutStderr, err := cmd.CombinedOutput()
			if stdoutStderr != nil {
				log.Printf("%s\n", stdoutStderr)
			}
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func main() {
	flag.Parse()
	var attempt int64 = 0
	connected := false
	for {
		attempt += 1
		conn, err := grpc.Dial(*server_address, grpc.WithInsecure())
		if err != nil {
			log.Printf("failed to connect: %s", err)
		}
		defer conn.Close()
		client := pb.NewWhitelistClient(conn)
		stream, err := client.Transfer(context.Background())

		msg := &pb.WhitelistRequest{Attempt: attempt}
		if err := stream.Send(msg); err != nil {
			log.Printf("%v.Send(%v) = %v", stream, msg, err)
			// todo: multiply by attempt, cap at 60 seconds, but how to convert int64 to int?
			time.Sleep(5 * time.Second)
			continue
		}
		connected = true
		log.Println("Connected to Server...")
		for connected == true {
			response, err := stream.Recv()
			if err != nil {
				log.Printf("%v.Recv() got error %v", stream, err)
				connected = false
				continue
			}
			send_whitelist_to_nftables(response.Whitelist)
			log.Printf("Whitelist on captive portal client: %v", response)
		}
	}
}
