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
  "testing"
  "sync"
	pb "github.com/wogri/captive_portal/proto"
)

type ComparableWhitelistEntry pb.WhitelistEntry

// As I didn't find a way how to compare protos I implemented one here.
// Whitelist Entries need to be casted to ComparableWhitelistEntries to make
// this work.
func (a *ComparableWhitelistEntry) Compare(b *ComparableWhitelistEntry) bool {
  return (a.Ipv6Address == b.Ipv6Address &&
          a.Ipv4Address == b.Ipv4Address &&
          a.ValidUntil == b.ValidUntil)
}

// A helper function to compare whitelist entries.
func compare_whitelist_entries(left []*pb.WhitelistEntry,
    right []*pb.WhitelistEntry, skip_next_comparison bool) bool {
  for _, left_elem := range left {
    elem_found := false
    for _, right_elem := range right {
      comp_left := ComparableWhitelistEntry(*left_elem)
      comp_right := ComparableWhitelistEntry(*right_elem)
      if comp_left.Compare(&comp_right) {
        elem_found = true
        break
      }
    }
    if !elem_found {
      return false
    }
  }
  if skip_next_comparison {
    return true
  }
  return compare_whitelist_entries(right, left, true)
}

func TestCheckPasswordHash(t *testing.T) {
  if !CheckPasswordHash("test",
      "$2a$14$5MZ5lpDsbChuolEOcJBT7.b/QIo6UMqN/1Amza6LeI3zlwlc2bIty") {
    t.Error("CheckPasswordHash is wrong, got: False, want: True.")
  }
}

func TestExpireWhitelist(t *testing.T) {
  whitelist_reply_mutex = &sync.Mutex{}
  entries := []*pb.WhitelistEntry{
    {Ipv4Address: "192.168.1.1",
     ValidUntil: 12345,
    },
    {Ipv6Address: "::1",
     ValidUntil: 12346,
    },
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 12347,
    },
  }
  reply := &pb.WhitelistReply{Whitelist: entries}
  expire_whitelist(reply, 12346)
  expected_entries := []*pb.WhitelistEntry{
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 12347,
    },
  }
  if !compare_whitelist_entries(expected_entries, reply.Whitelist, false) {
    t.Errorf("Whitelist Entries do not match:\n%v\n%v", expected_entries,
        reply.Whitelist)
  }
}

func TestDedupWhitelistWithDupes(t *testing.T) {
  whitelist_reply_mutex = &sync.Mutex{}
  entries := []*pb.WhitelistEntry{
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 99999,
    },
    {Ipv4Address: "192.168.1.1",
     ValidUntil: 12345,
    },
    {Ipv6Address: "::1",
     ValidUntil: 12346,
    },
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 12347,
    },
  }
  reply := &pb.WhitelistReply{Whitelist: entries}
  dedup_whitelist(reply)
  expected_entries := []*pb.WhitelistEntry{
    {Ipv4Address: "192.168.1.1",
     ValidUntil: 12345,
    },
    {Ipv6Address: "::1",
     ValidUntil: 12346,
    },
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 12347,
    },
  }
  if !compare_whitelist_entries(expected_entries, reply.Whitelist, false) {
    t.Errorf("Dedupe did not work:\n%v\n%v", expected_entries, reply.Whitelist)
  }
}

func TestDedupWhitelistWithNoDupes(t *testing.T) {
  whitelist_reply_mutex = &sync.Mutex{}
  entries := []*pb.WhitelistEntry{
    {Ipv4Address: "192.168.1.1",
     ValidUntil: 12345,
    },
    {Ipv6Address: "::1",
     ValidUntil: 12346,
    },
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 12347,
    },
  }
  reply := &pb.WhitelistReply{Whitelist: entries}
  dedup_whitelist(reply)
  expected_entries := []*pb.WhitelistEntry{
    {Ipv4Address: "192.168.1.1",
     ValidUntil: 12345,
    },
    {Ipv6Address: "::1",
     ValidUntil: 12346,
    },
    {Ipv6Address: "fe80::6f45:c4cf:caf:6ad0",
     ValidUntil: 12347,
    },
  }
  if !compare_whitelist_entries(expected_entries, reply.Whitelist, false) {
    t.Errorf("Deduped too much:\n%v\n%v", expected_entries, reply.Whitelist)
  }
}

func TestParseWhitelistEntry(t *testing.T) {
  // I know the parser is not perfect, so these tests are not perfect either.
  entry, err := parse_whitelist_entry("192.123.123.123")
  if err != nil {
    t.Error("Entry-Parser is at fault")
  }
  if entry.Ipv4Address != "192.123.123.123" {
    t.Error("Entry-Parser is at fault")
  }
  entry, err = parse_whitelist_entry("[affe:dead:beef::1]:12345")
  if err != nil {
    t.Error("Entry-Parser is at fault")
  }
  if entry.Ipv6Address != "affe:dead:beef::1" {
    t.Error("Entry-Parser is at fault")
  }
  entry, err = parse_whitelist_entry("fe80::aede:48ff:fe00:1122")
  if err != nil {
    t.Error("Entry-Parser is at fault")
  }
  if entry.Ipv6Address != "fe80::aede:48ff:fe00:1122" {
    t.Error("Entry-Parser is at fault")
  }
  entry, err = parse_whitelist_entry("::1")
  if err != nil {
    t.Error("Entry-Parser is at fault")
  }
  if entry.Ipv6Address != "::1" {
    t.Error("Entry-Parser is at fault")
  }
  _, err = parse_whitelist_entry("192.asdf.xyz.123")
  if err == nil {
    t.Error("Entry-Parser is at fault")
  }
  _, err = parse_whitelist_entry("192.168.1.1.1")
  if err == nil {
    t.Error("Entry-Parser is at fault")
  }
  _, err = parse_whitelist_entry("::1;rm -rf /")
  if err == nil {
    t.Error("Entry-Parser is at fault")
  }
  _, err = parse_whitelist_entry("asdf")
  if err == nil {
    t.Error("Entry-Parser is at fault")
  }
  _, err = parse_whitelist_entry("")
  if err == nil {
    t.Error("Entry-Parser is at fault")
  }
}

func TestChannelHandlerRemoval(t *testing.T) {
  channel_handler := &ChannelHandler{mutex: &sync.Mutex{}}
  chan_a := channel_handler.AddNewChannel()
  chan_b := channel_handler.AddNewChannel()
  chan_c := channel_handler.AddNewChannel()
  if !channel_handler.RemoveChannel(chan_b) {
    t.Error("Channel Removal did not work!")
    return
  }
  go func() {
    channel_handler.PingChannels()
  }()
  a := <-*chan_a
  c := <-*chan_c
  if !(a && c) {
    t.Error("Channel Handler does not correctly ping channels.")
  }
}

func TestChannelHandlerPing(t *testing.T) {
  channel_handler := &ChannelHandler{mutex: &sync.Mutex{}}
  chan_a := channel_handler.AddNewChannel()
  chan_b := channel_handler.AddNewChannel()
  chan_c := channel_handler.AddNewChannel()
  go func() {
    channel_handler.PingChannels()
  }()
  a := <-*chan_a
  b := <-*chan_b
  c := <-*chan_c
  if !(a && b && c) {
    t.Error("Channel Handler does not correctly ping channels.")
  }
}
