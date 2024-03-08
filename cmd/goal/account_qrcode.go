package main

import (
	"fmt"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/mr-tron/base58"

	qrcode "github.com/xi/go-tinyqr"
)

// print Online/Offline ARC-XXX QR Code to stdout
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
	url := buildARCXXXURL(address, goOnline, part)
	return qrcode.Print(url)
}

const ARCXXXURLHANDLER = "web+algorand+onl"

// print Online/Offline ARC-XXX URL
func buildARCXXXURL(address basics.Address, goOnline bool, part model.ParticipationKey) string {

	//use Base58 for URLs
	vpk58 := base58.Encode(part.Key.VoteParticipationKey)
	spk58 := base58.Encode(part.Key.SelectionParticipationKey)
	addr58 := base58.Encode(address[:])

	if goOnline {
		return fmt.Sprintf("%s://%d/%s/%d/%d/%s/%s",
			ARCXXXURLHANDLER,
			1,
			addr58,
			part.Key.VoteFirstValid,
			part.Key.VoteLastValid,
			vpk58,
			spk58,
		)
	}
	return fmt.Sprintf("%s://%d/%s",
		ARCXXXURLHANDLER,
		0,
		addr58,
	)
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
