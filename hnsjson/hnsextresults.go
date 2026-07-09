// Copyright (c) 2016-2017 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsjson

// NameStateResult models the persisted chain state for a Handshake name.
type NameStateResult struct {
	Name       string `json:"name"`
	NameHash   string `json:"namehash"`
	Height     uint32 `json:"height"`
	Renewal    uint32 `json:"renewal"`
	OwnerHash  string `json:"ownerhash"`
	OwnerIndex uint32 `json:"ownerindex"`
	Value      int64  `json:"value"`
	Highest    int64  `json:"highest"`
	Data       string `json:"data"`
	Transfer   uint32 `json:"transfer"`
	Revoked    uint32 `json:"revoked"`
	Claimed    uint32 `json:"claimed"`
	Renewals   uint32 `json:"renewals"`
	Registered bool   `json:"registered"`
	Expired    bool   `json:"expired"`
	Weak       bool   `json:"weak"`
}

// GetNameInfoResult models the response to getnameinfo and getnamebyhash.
type GetNameInfoResult struct {
	Found bool             `json:"found"`
	State *NameStateResult `json:"state,omitempty"`
}

// NameResourceRecordResult models a decoded Handshake DNS resource record.
type NameResourceRecordResult struct {
	Type       string   `json:"type"`
	TypeID     uint8    `json:"typeid"`
	Name       string   `json:"name,omitempty"`
	Address    string   `json:"address,omitempty"`
	KeyTag     uint16   `json:"keytag,omitempty"`
	Algorithm  uint8    `json:"algorithm,omitempty"`
	DigestType uint8    `json:"digesttype,omitempty"`
	Digest     string   `json:"digest,omitempty"`
	Items      []string `json:"items,omitempty"`
}

// NameResourceDataResult models decoded Handshake name resource data.
type NameResourceDataResult struct {
	Version uint8                       `json:"version"`
	Records []*NameResourceRecordResult `json:"records"`
}

// GetNameResourceResult models the response to getnameresource.
type GetNameResourceResult struct {
	Name     string                  `json:"name"`
	NameHash string                  `json:"namehash"`
	Found    bool                    `json:"found"`
	Data     string                  `json:"data,omitempty"`
	Resource *NameResourceDataResult `json:"resource,omitempty"`
}

// GetNameProofResult models the response to getnameproof.
type GetNameProofResult struct {
	Name     string `json:"name"`
	NameHash string `json:"namehash"`
	Root     string `json:"root"`
	Proof    string `json:"proof"`
}

// GetAuctionInfoResult models the response to getauctioninfo.
type GetAuctionInfoResult struct {
	Name                 string `json:"name"`
	NameHash             string `json:"namehash"`
	Found                bool   `json:"found"`
	Phase                string `json:"phase"`
	CurrentHeight        uint32 `json:"currentheight"`
	StartHeight          uint32 `json:"startheight,omitempty"`
	BiddingStart         uint32 `json:"biddingstart,omitempty"`
	RevealStart          uint32 `json:"revealstart,omitempty"`
	CloseHeight          uint32 `json:"closeheight,omitempty"`
	NextHeight           uint32 `json:"nextheight,omitempty"`
	OwnerHash            string `json:"ownerhash,omitempty"`
	OwnerIndex           uint32 `json:"ownerindex,omitempty"`
	Value                int64  `json:"value,omitempty"`
	Highest              int64  `json:"highest,omitempty"`
	RenewalHeight        uint32 `json:"renewalheight,omitempty"`
	ExpirationHeight     uint32 `json:"expirationheight,omitempty"`
	TransferUnlockHeight uint32 `json:"transferunlockheight,omitempty"`
	RevokeMaturityHeight uint32 `json:"revokematurityheight,omitempty"`
	Registered           bool   `json:"registered"`
	Expired              bool   `json:"expired"`
	Weak                 bool   `json:"weak"`
}

// VerifyNameProofResult models the response to verifynameproof.
type VerifyNameProofResult struct {
	Root     string `json:"root"`
	NameHash string `json:"namehash"`
	Exists   bool   `json:"exists"`
	Value    string `json:"value,omitempty"`
}

// VersionResult models objects included in the version response.  In the actual
// result, these objects are keyed by the program or API name.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
type VersionResult struct {
	VersionString string `json:"versionstring"`
	Major         uint32 `json:"major"`
	Minor         uint32 `json:"minor"`
	Patch         uint32 `json:"patch"`
	Prerelease    string `json:"prerelease"`
	BuildMetadata string `json:"buildmetadata"`
}
