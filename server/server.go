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
	pb "github.com/wogri/nft-firewall-holepuncher/whitelist"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	grpc_port            = flag.String("grpc_port", "8081", "Bind grpc to port")
	http_port            = flag.String("http_port", "8080", "Bind http to port")
	password_hash        = flag.String("password_hash", "", "Bcrypt password hash")
	redirect_success_url = flag.String(
		"redirect_success_url",
		"",
		"URL to redirect after successful password entry")
	redirect_failure_url = flag.String(
		"redirect_failure_url", "", "URL to redirect after failed password entry")
	whitelist_reply       *pb.WhitelistReply
	whitelist_reply_mutex *sync.Mutex
	use_http_header_ip    = flag.String(
		"use_http_header_ip",
		"",
		"Use http header to extract source ip address instead of real source ip. "+
			"For usage behind proxies. An example option could be: X-Real-IP:")
  // The channels are merely there for signaling that there's something new.
	channel_handler *ChannelHandler
)

type whitelistServer struct{
  pb.UnimplementedWhitelistServer
}

type RegexParseError struct {
	Problem string
}

type ChannelHandler struct {
  channels []*chan bool
  mutex *sync.Mutex
}

func (e *RegexParseError) Error() string {
	return e.Problem
}

func (w *ChannelHandler) AddNewChannel() *chan bool {
  channel := make(chan bool)
  w.mutex.Lock()
  w.channels = append(w.channels, &channel)
  w.mutex.Unlock()
  return &channel
}

func (w *ChannelHandler) RemoveChannel(dead_channel *chan bool) bool {
  w.mutex.Lock()
  defer w.mutex.Unlock()
  for index, channel := range w.channels {
    if channel == dead_channel {
      w.channels = append(w.channels[:index], w.channels[index + 1:]...)
      return true
    }
  }
  return false
}

func (w *ChannelHandler) PingChannels() {
  // sends every channel a true, to wakeup the waiting client threads.
  w.mutex.Lock()
  defer w.mutex.Unlock()
  for _, channel := range w.channels {
    *channel <- true
  }
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func expire_whitelist(list *pb.WhitelistReply, now int64) {
	newlist := &pb.WhitelistReply{}
	whitelist_reply_mutex.Lock()
	defer whitelist_reply_mutex.Unlock()
	for _, entry := range list.Whitelist {
		if entry.ValidUntil > now {
			newlist.Whitelist = append(newlist.Whitelist, entry)
		}
	}
	*list = *newlist
}
func dedup_whitelist(list *pb.WhitelistReply) {
	mymap := make(map[string]bool)
	newlist := &pb.WhitelistReply{}
	whitelist_reply_mutex.Lock()
	defer whitelist_reply_mutex.Unlock()
	// Go through whitelist in reverse order, so if somebody updates an existing
	// element, it gets the latest valid_until element.
	for i := len(list.Whitelist) - 1; i >= 0; i-- {
		entry := list.Whitelist[i]
		var addr string
		if temp_addr := entry.GetIpv4Address(); temp_addr != "" {
			addr = temp_addr
		}
		if temp_addr := entry.GetIpv6Address(); temp_addr != "" {
			addr = temp_addr
		}
		if _, present := mymap[addr]; !present {
			newlist.Whitelist = append(newlist.Whitelist, entry)
			mymap[addr] = true
		} else {
			mymap[addr] = true
		}
	}
	*list = *newlist
}

func parse_whitelist_entry(ip string) (*pb.WhitelistEntry, error) {
	var whitelist_entry *pb.WhitelistEntry
	valid_until := int64(time.Now().Unix()) + 2*60*60
	if matched, _ := regexp.MatchString(`^(\d+\.){3}\d+(:\d+)?$`, ip); matched {
		ips := strings.Split(ip, ":")
    if len(ips) > 0 {
      ip = ips[0]
		} else {
			return nil, &RegexParseError{"Regex Parse Error, couldn't find any element."}
    }
		whitelist_entry = &pb.WhitelistEntry{
			Ipv4Address: ip,
			ValidUntil:  valid_until,
		}
	} else {
		re := regexp.MustCompile(`^\[?([a-fA-F0-9:]+)\]?(:\d+)?$`)
		ips := re.FindStringSubmatch(ip)
		if len(ips) > 1 {
			ip = ips[1]
		} else {
			return nil, &RegexParseError{"Regex Parse Error, couldn't find more than one element."}
		}
		whitelist_entry = &pb.WhitelistEntry{
			Ipv6Address: ip,
			ValidUntil:  valid_until,
		}
	}
	return whitelist_entry, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		_ = r.ParseForm
		password := r.FormValue("password")
		hash, _ := HashPassword(password)
		if CheckPasswordHash(password, *password_hash) {
			log.Print("Password Correct. Hash: ", hash)
			var ip string
			if *use_http_header_ip != "" {
				ip = r.Header.Get(*use_http_header_ip)
			} else {
				ip = r.RemoteAddr
			}
			whitelist_entry, err := parse_whitelist_entry(ip)
			if err != nil {
				log.Println(err)
				return
			}
      expire_whitelist(whitelist_reply, int64(time.Now().Unix()))
      whitelist_reply_mutex.Lock()
      whitelist_reply.Whitelist = append(whitelist_reply.Whitelist, whitelist_entry)
      whitelist_reply_mutex.Unlock()
      dedup_whitelist(whitelist_reply)
      log.Printf("latest whitelist_entries: %v", whitelist_reply.Whitelist)
      channel_handler.PingChannels()

			http.Redirect(w, r, *redirect_success_url, 301)
		} else {
			log.Printf(
				"Password Incorrect. Password was: %v which corresponds to hash %v",
				password,
				hash)
			http.Redirect(w, r, *redirect_failure_url, 301)
		}
	} else {
		http.NotFound(w, r)
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *whitelistServer) Transfer(stream pb.Whitelist_TransferServer) error {
	for {
		_, err := stream.Recv()
		if err != nil {
			log.Printf("Error stream.Recv: %v", err)
			return err
		}
		expire_whitelist(whitelist_reply, int64(time.Now().Unix()))

    channel := channel_handler.AddNewChannel()
		for {
			whitelist_reply_mutex.Lock()
			log.Printf("Sending down whitelist to client")
			if err := stream.Send(whitelist_reply); err != nil {
			  whitelist_reply_mutex.Unlock()
				log.Printf("Error stream.Send: %v", err)
        channel_handler.RemoveChannel(channel)
				return err
			}
			whitelist_reply_mutex.Unlock()
      // just listen for an event on the chanel, we don't care about the content
      <-*channel
		}
	}
}

func main() {
	flag.Parse()
	http.HandleFunc("/", notFound)
	http.HandleFunc("/login", login)
	whitelist_reply = &pb.WhitelistReply{}
	whitelist_reply_mutex = &sync.Mutex{}
	grpcServer := grpc.NewServer()
  channel_handler = &ChannelHandler{mutex: &sync.Mutex{}}
	pb.RegisterWhitelistServer(grpcServer, &whitelistServer{})

	l, err := net.Listen("tcp", ":"+*grpc_port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// http server - needs to be running in its own thread, otherwise blocks.
	go func() {
		log.Println("Listening for http on tcp://localhost:" + *http_port)
		log.Fatal(http.ListenAndServe(":"+*http_port, nil))
	}()

	// grpc server listening on a separate port
	log.Println("Listening for grpc on tcp://localhost:" + *grpc_port)
	grpcServer.Serve(l)
}
