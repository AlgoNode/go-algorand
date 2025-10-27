// Copyright (C) 2019-2025 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package ledger

import (
	"context"
	"encoding/binary"
	"math"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
)

// TXIDBloomFilter defines the interface for a bloom filter that can test
// membership of transaction IDs in a set.
type TXIDBloomFilter interface {
	// Add inserts a transaction ID into the bloom filter
	Add(txid transactions.Txid)

	// Test checks if a transaction ID might be in the set.
	// Returns true if the txid might be present (with possible false positives)
	// or false if definitely not present (no false negatives).
	Test(txid transactions.Txid) bool

	// Reset clears all entries from the bloom filter
	Reset()
}

const (
	// numHashFunctions is the number of hash functions used by the bloom filter.
	// We use k=8 as specified, which allows us to extract 8 uint32 values from
	// the 32-byte transaction ID (8 * 4 bytes = 32 bytes).
	numHashFunctions = 8

	// defaultFalsePositiveRate is the target false positive rate for the bloom filter.
	// A rate of 0.001 (0.1%) provides a good balance between memory usage and accuracy.
	defaultFalsePositiveRate = 0.001
)

// fastTXIDBloomFilter implements FastTXIDBloomFilter using a bit array.
// It uses an optimized approach where the 32-byte transaction ID is directly
// interpreted as 8 uint32 hash values, avoiding the need for hash computation.
type fastTXIDBloomFilter struct {
	// bits is the bit array for the bloom filter
	bits []byte

	// numBits is the total number of bits in the filter
	numBits uint32
}

// createFastTXIDBloomFilter creates a new FastTXIDBloomFilter optimized for the
// expected number of elements. It uses the optimal bloom filter sizing algorithm
// to minimize false positives while keeping memory usage reasonable.
//
// Parameters:
//   - numElements: Expected number of transaction IDs to store in the filter
//
// Returns:
//   - A new FastTXIDBloomFilter instance
func createFastTXIDBloomFilter(numElements int) TXIDBloomFilter {
	// Handle edge case of empty or very small filters
	if numElements <= 0 {
		numElements = 1
	}

	// Calculate optimal number of bits using the standard bloom filter formula:
	// m = -(n * ln(p)) / (ln(2)^2)
	// where n = number of elements, p = false positive rate, m = number of bits
	//
	// This formula is derived from minimizing the false positive probability
	// for a given number of elements and hash functions.
	n := float64(numElements)
	p := defaultFalsePositiveRate
	m := -(n+0.5)*math.Log(p)/math.Pow(math.Log(2), 2) + 1

	numBits := uint32(math.Ceil(m))

	// Calculate the number of bytes needed (round up to nearest byte)
	numBytes := (numBits + 7) / 8

	return &fastTXIDBloomFilter{
		bits:    make([]byte, numBytes),
		numBits: numBits,
	}
}

// Add inserts a transaction ID into the bloom filter by setting the corresponding
// bits for all hash functions.
func (f *fastTXIDBloomFilter) Add(txid transactions.Txid) {
	// extracts 8 uint32 hash values directly from the 32-byte transaction ID.
	// This is an optimization that treats the txid bytes as pre-computed hash values,
	// avoiding the computational cost of running hash functions.
	//
	// The transaction ID is already a cryptographic hash (SHA-512/256), so its bytes
	// are uniformly distributed and suitable for use as hash values.

	for i := 0; i < numHashFunctions; i++ {
		// Use little-endian byte order for consistency
		h := binary.LittleEndian.Uint32(txid[i<<2 : (i<<2)+4])
		// Map hash value to bit position using modulo
		bit := h % f.numBits

		// Set the bit at the calculated position
		f.bits[bit>>3] |= 1 << (bit & 7)
	}
}

// Test checks if a transaction ID might be present in the bloom filter.
// Returns true if all corresponding bits are set (might be present, with possible
// false positives), or false if any bit is not set (definitely not present).
func (f *fastTXIDBloomFilter) Test(txid transactions.Txid) bool {
	for i := 0; i < numHashFunctions; i++ {
		// Use little-endian byte order for consistency
		h := binary.LittleEndian.Uint32(txid[i<<2 : (i<<2)+4])
		// Map hash value to bit position using modulo
		bit := h % f.numBits

		// Check if the bit is set
		if f.bits[bit>>3]&(1<<(bit&7)) == 0 {
			// If any bit is not set, the element is definitely not present
			return false
		}
	}

	// All bits are set, element might be present (could be false positive)
	return true
}

// Reset clears all entries from the bloom filter by zeroing the bit array.
func (f *fastTXIDBloomFilter) Reset() {
	for i := range f.bits {
		f.bits[i] = 0
	}
}

// txidBloomFilter is a ledger tracker that maintains bloom filters for transaction IDs
// for the most recent MaxTxnLife rounds. This allows for efficient probabilistic
// duplicate transaction detection.
type txidBloomFilter struct {
	// mu protects access to all fields in this struct
	mu deadlock.RWMutex

	// filters maps round numbers to their corresponding bloom filters
	// Contains bloom filters for approximately the last MaxTxnLife rounds
	filters map[basics.Round]TXIDBloomFilter

	// lowestRound tracks the oldest round we have a bloom filter for
	lowestRound basics.Round

	// maxTxnLife is the maximum transaction lifetime from consensus parameters
	// This determines how many rounds worth of bloom filters we maintain
	maxTxnLife uint64

	// log is the logger for this tracker
	log logging.Logger
}

// loadFromDisk initializes the txidBloomFilter tracker by loading the last MaxTxnLife
// rounds worth of blocks and populating bloom filters with their transaction IDs.
func (t *txidBloomFilter) loadFromDisk(l ledgerForTracker, dbRound basics.Round) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.log = l.trackerLog()
	t.filters = make(map[basics.Round]TXIDBloomFilter)

	// Get the latest round from the ledger
	latestRound := l.Latest()

	// Determine the consensus parameters to get MaxTxnLife
	if dbRound > 0 {
		blk, err := l.Block(dbRound)
		if err != nil {
			return err
		}
		consensusParams := config.Consensus[blk.CurrentProtocol]
		t.maxTxnLife = consensusParams.MaxTxnLife
	} else {
		// Use genesis consensus params as fallback
		genesisProto := l.GenesisProto()
		t.maxTxnLife = genesisProto.MaxTxnLife
	}

	// Calculate the starting round (earliest round we need to load)
	// We want the last MaxTxnLife rounds
	startRound := latestRound.SubSaturate(basics.Round(t.maxTxnLife))
	if startRound < dbRound.SubSaturate(basics.Round(t.maxTxnLife)) {
		startRound = dbRound.SubSaturate(basics.Round(t.maxTxnLife))
	}

	t.lowestRound = startRound

	for rnd := latestRound; rnd >= startRound; rnd-- {
		blk, err := l.Block(rnd)
		if err != nil {
			t.log.Warnf("txifBloomFilter: filed to load round %d", rnd)
			return err
		}
		if err = t.parseBlock(blk); err != nil {
			return err
		}
	}

	t.log.Infof("txidBloomFilter: initialized with MaxTxnLife=%d, lowestRound=%d, latestRound=%d",
		t.maxTxnLife, t.lowestRound, latestRound)

	return nil
}

func (t *txidBloomFilter) parseBlock(blk bookkeeping.Block) error {
	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return err
	}
	rnd := blk.Round()
	t.filters[rnd] = createFastTXIDBloomFilter(len(payset))

	for _, tx := range payset {
		t.filters[rnd].Add(tx.ID())
	}
	return nil
}

// newBlock is called when a new block is added to the ledger.
// It creates a new bloom filter for the block's round and populates it with
// all transaction IDs from the block.
func (t *txidBloomFilter) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rnd := blk.Round()
	if err := t.parseBlock(blk); err != nil {
		return
	}

	t.log.Debugf("txidBloomFilter: added bloom filter for round %d with %d transactions",
		rnd, len(blk.Payset))
}

// committedUpTo is called when blocks up to the given round have been committed to disk.
// It removes bloom filters for rounds that are older than MaxTxnLife to free up memory.
// Returns the minimum round that needs to be kept in the block database.
func (t *txidBloomFilter) committedUpTo(committedRound basics.Round) (minRound, lookback basics.Round) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Calculate the oldest round we need to keep
	// We need to keep MaxTxnLife rounds
	minRound = committedRound.SubSaturate(basics.Round(t.maxTxnLife))

	// Remove bloom filters for rounds older than minRound
	for rnd := range t.filters {
		if rnd < minRound {
			delete(t.filters, rnd)
			t.log.Debugf("txidBloomFilter: removed bloom filter for round %d", rnd)
		}
	}

	// Update lowestRound to reflect the oldest bloom filter we still have
	if minRound > t.lowestRound {
		t.lowestRound = minRound
	}

	// Return the lookback value (MaxTxnLife rounds)
	lookback = basics.Round(t.maxTxnLife)

	return minRound, lookback
}

// produceCommittingTask is called to prepare data for committing to the database.
// For this tracker, we don't need to persist bloom filters to disk, so we just
// pass through the deferredCommitRange unchanged.
func (t *txidBloomFilter) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	// Bloom filters are kept in memory only, so we don't need to modify the deferredCommitRange
	return dcr
}

// prepareCommit is called to prepare for committing data to the database.
// Since we don't persist bloom filters, this is a no-op.
func (t *txidBloomFilter) prepareCommit(dcc *deferredCommitContext) error {
	// Nothing to prepare for commit - bloom filters are memory-only
	return nil
}

// commitRound is called to commit data to the database within a transaction.
// Since we don't persist bloom filters, this is a no-op.
func (t *txidBloomFilter) commitRound(ctx context.Context, tx trackerdb.TransactionScope, dcc *deferredCommitContext) error {
	// Nothing to commit - bloom filters are memory-only
	return nil
}

// postCommit is called after a successful commit to update internal state.
// For this tracker, we don't need to do anything here since cleanup happens in committedUpTo.
func (t *txidBloomFilter) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	// Nothing to do post-commit
}

// close terminates the tracker and releases resources.
func (t *txidBloomFilter) close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Clear all bloom filters to free memory
	t.filters = nil
	t.log.Debug("txidBloomFilter: closed")
}

// Test checks if a transaction ID might exist in any of the maintained bloom filters.
// Returns true if the txid might be present (with possible false positives)
// or false if definitely not present.
func (t *txidBloomFilter) TXIDMightExistsInBlock(txid transactions.Txid, rnd basics.Round) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Check if we have a bloom filter for the given round
	filter, ok := t.filters[rnd]
	if !ok || filter == nil {
		// No bloom filter for this round
		// Return "might be present" as we have no data to confirm otherwise
		return true
	}

	return filter.Test(txid)
}
