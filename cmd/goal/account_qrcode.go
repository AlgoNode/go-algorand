package main

import (
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"

	qrcode "github.com/xi/go-tinyqr"
)

const ARC0026URLHANDLER = "algorand"
const ARC0026TYPEKEYREG = "keyreg"

// QRKeyregRequest captures the fields used for key registration transactions in QR Code form.
type QRKeyregRequest struct {
	model.AccountParticipation
	Sender basics.Address
	Online bool
}

func (krg QRKeyregRequest) URI() string {
	var bitOnline int8
	strSender := krg.Sender.String()
	if krg.Online {
		bitOnline = 1
		strVotePK := base64.RawURLEncoding.EncodeToString(krg.VoteParticipationKey)
		strSelPK := base64.RawURLEncoding.EncodeToString(krg.SelectionParticipationKey)
		strStprfPK := base64.RawURLEncoding.EncodeToString(*krg.StateProofKey)
		return fmt.Sprintf("%s://%s?t=%s&onl=%d&vpk=%s&spk=%s&stprf=%s&vf=%d&vl=%d&vd=%d",
			ARC0026URLHANDLER,
			strSender,
			ARC0026TYPEKEYREG,
			bitOnline,
			strVotePK,
			strSelPK,
			strStprfPK,
			krg.VoteFirstValid,
			krg.VoteLastValid,
			krg.VoteKeyDilution,
		)
	}
	return fmt.Sprintf("%s://%s?t=%s&onl=%d",
		ARC0026URLHANDLER,
		strSender,
		ARC0026TYPEKEYREG,
		bitOnline,
	)
}

func (krg QRKeyregRequest) Print() {
	uri := krg.URI()
	fmt.Println("Paste below URL into your browser or scan QR code to online/offline the account")
	fmt.Println(uri)
	fmt.Println()
	qrcode.Print(uri)
}

func (krg QRKeyregRequest) String() string {
	return krg.URI()
}

// print Online/Offline ARC-0026 QR Code to stdout
func showAccountOnlineQRCode(
	acct string, goOnline bool, client libgoal.Client,
) error {
	// Make sure address is valid
	address, err := basics.UnmarshalChecksumAddress(acct)
	if err != nil {
		return err
	}

	part, err := getCandidatePartKey(acct, client)
	if err != nil {
		return err
	}
	kregreq := makeQRKeyRegRequest(address, goOnline, part)
	kregreq.Print()
	return nil
}

// create QRKeyRegRequest struct for the given address and operation
func makeQRKeyRegRequest(address basics.Address, goOnline bool, part model.ParticipationKey) *QRKeyregRequest {

	req := &QRKeyregRequest{
		Online: goOnline,
		Sender: address,
	}

	//Copy public partcipation key info when going online
	if goOnline {
		req.AccountParticipation = part.Key
	}

	return req
}

func getCandidatePartKey(address string, c libgoal.Client) (part model.ParticipationKey, err error) {

	params, err := c.SuggestedParams()
	if err != nil {
		return part, err
	}

	// Safe to use in this manual process
	round := params.LastRound - 1

	parts, err := c.ListParticipationKeys()
	if err != nil {
		return
	}

	// Loop through each of the participation keys; pick the one that expires farthest in the future.
	var expiry uint64 = 0
	for _, info := range parts {
		// Choose the Participation valid for this round that relates to the passed address
		// that expires farthest in the future.
		// Note that algod will sign votes with all possible Participations. so any should work
		// in the short-term.
		// In the future we should allow the user to specify exactly which partkeys to register.
		if info.Key.VoteFirstValid <= uint64(round) && uint64(round) <= info.Key.VoteLastValid && info.Address == address && info.Key.VoteLastValid > expiry {
			part = info
			expiry = part.Key.VoteLastValid
		}

	}
	if part.Address == "" {
		// Couldn't find one
		err = fmt.Errorf("couldn't find a participation key database for address %v valid at round %v in participation registry", address, round)
		return
	}
	return

}
