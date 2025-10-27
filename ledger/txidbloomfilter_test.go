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
	"crypto/rand"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestFastTXIDBloomFilter_BasicOperations tests the basic Add and Test operations
func TestFastTXIDBloomFilter_BasicOperations(t *testing.T) {
	partitiontest.PartitionTest(t)

	filter := createFastTXIDBloomFilter(100)

	// Generate a random transaction ID
	var txid transactions.Txid
	_, err := rand.Read(txid[:])
	require.NoError(t, err)

	// Test should return false before adding
	require.False(t, filter.Test(txid), "Transaction ID should not be present before adding")

	// Add the transaction ID
	filter.Add(txid)

	// Test should return true after adding
	require.True(t, filter.Test(txid), "Transaction ID should be present after adding")
}

// TestFastTXIDBloomFilter_MultipleTxids tests adding and testing multiple transaction IDs
func TestFastTXIDBloomFilter_MultipleTxids(t *testing.T) {
	partitiontest.PartitionTest(t)

	numTxids := 10_000
	filter := createFastTXIDBloomFilter(numTxids)

	// Generate and add multiple transaction IDs
	txids := make([]transactions.Txid, numTxids)
	for i := 0; i < numTxids; i++ {
		_, err := rand.Read(txids[i][:])
		require.NoError(t, err)
		filter.Add(txids[i])
	}

	// Verify all added transaction IDs are found
	for i, txid := range txids {
		require.True(t, filter.Test(txid), "Transaction ID %d should be present", i)
	}

	// Generate and test transaction IDs that were not added
	// These should mostly return false, but false positives are possible
	notAddedCount := 10_000
	falsePositives := 0
	for i := 0; i < notAddedCount; i++ {
		var txid transactions.Txid
		_, err := rand.Read(txid[:])
		require.NoError(t, err)

		if filter.Test(txid) {
			falsePositives++
		}
	}

	// With a 0.1% false positive rate and 10000 tests, we expect around 10 false positive
	// Allow up to 1% to account for random variance
	require.Less(t, falsePositives, notAddedCount/100,
		"False positive rate too high: %d/%d", falsePositives, notAddedCount)
}

// TestFastTXIDBloomFilter_Reset tests the Reset functionality
func TestFastTXIDBloomFilter_Reset(t *testing.T) {
	partitiontest.PartitionTest(t)

	filter := createFastTXIDBloomFilter(10)

	// Add several transaction IDs
	txids := make([]transactions.Txid, 5)
	for i := 0; i < len(txids); i++ {
		_, err := rand.Read(txids[i][:])
		require.NoError(t, err)
		filter.Add(txids[i])
	}

	// Verify they are present
	for i, txid := range txids {
		require.True(t, filter.Test(txid), "Transaction ID %d should be present before reset", i)
	}

	// Reset the filter
	filter.Reset()

	// Verify the transaction IDs are no longer present
	for i, txid := range txids {
		require.False(t, filter.Test(txid), "Transaction ID %d should not be present after reset", i)
	}
}

// TestFastTXIDBloomFilter_EmptyFilter tests filter behavior with zero elements
func TestFastTXIDBloomFilter_EmptyFilter(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Create filter with 0 elements (should handle gracefully)
	filter := createFastTXIDBloomFilter(0)
	require.NotNil(t, filter)

	// Test with a random transaction ID
	var txid transactions.Txid
	_, err := rand.Read(txid[:])
	require.NoError(t, err)

	// Should return false for non-existent element
	require.False(t, filter.Test(txid))

	// Add the element
	filter.Add(txid)

	// Should return true after adding
	require.True(t, filter.Test(txid))
}

// TestFastTXIDBloomFilter_SingleElement tests filter with a single element
func TestFastTXIDBloomFilter_SingleElement(t *testing.T) {
	partitiontest.PartitionTest(t)

	filter := createFastTXIDBloomFilter(1)

	var txid transactions.Txid
	_, err := rand.Read(txid[:])
	require.NoError(t, err)

	filter.Add(txid)
	require.True(t, filter.Test(txid))
}

// TestFastTXIDBloomFilter_LargeCapacity tests filter with large capacity
func TestFastTXIDBloomFilter_LargeCapacity(t *testing.T) {
	partitiontest.PartitionTest(t)

	numElements := 75000
	filter := createFastTXIDBloomFilter(numElements)

	// Add transaction IDs
	sampleSize := 75000
	txids := make([]transactions.Txid, sampleSize)
	for i := 0; i < sampleSize; i++ {
		_, err := rand.Read(txids[i][:])
		require.NoError(t, err)
		filter.Add(txids[i])
	}

	// Verify all added transaction IDs are found
	for i, txid := range txids {
		require.True(t, filter.Test(txid), "Transaction ID %d should be present", i)
	}
}

// TestFastTXIDBloomFilter_DeterministicBehavior tests that the same txid always produces the same result
func TestFastTXIDBloomFilter_DeterministicBehavior(t *testing.T) {
	partitiontest.PartitionTest(t)

	filter := createFastTXIDBloomFilter(100)

	var txid transactions.Txid
	_, err := rand.Read(txid[:])
	require.NoError(t, err)

	// Add the transaction ID
	filter.Add(txid)

	// Test multiple times - should always return true
	for i := 0; i < 10; i++ {
		require.True(t, filter.Test(txid), "Transaction ID should consistently be found (iteration %d)", i)
	}
}

// TestFastTXIDBloomFilter_DifferentSizes tests filter creation with different sizes
func TestFastTXIDBloomFilter_DifferentSizes(t *testing.T) {
	partitiontest.PartitionTest(t)

	sizes := []int{1, 10, 100, 1000, 10000, 100000}

	for _, size := range sizes {
		filter := createFastTXIDBloomFilter(size)
		require.NotNil(t, filter, "Filter should be created for size %d", size)

		// Verify basic functionality
		var txid transactions.Txid
		_, err := rand.Read(txid[:])
		require.NoError(t, err)

		require.False(t, filter.Test(txid), "Size %d: txid should not be present initially", size)
		filter.Add(txid)
		require.True(t, filter.Test(txid), "Size %d: txid should be present after adding", size)
	}
}

// TestFastTXIDBloomFilter_NoFalseNegatives ensures there are never false negatives
func TestFastTXIDBloomFilter_NoFalseNegatives(t *testing.T) {
	partitiontest.PartitionTest(t)

	filter := createFastTXIDBloomFilter(100)

	// Add many transaction IDs and verify none produce false negatives
	numTests := 500
	for i := 0; i < numTests; i++ {
		var txid transactions.Txid
		_, err := rand.Read(txid[:])
		require.NoError(t, err)

		filter.Add(txid)
		require.True(t, filter.Test(txid),
			"No false negatives allowed: txid %d should be found immediately after adding", i)
	}
}

// TestFastTXIDBloomFilter_RealTxids tests with actual transaction ID format
func TestFastTXIDBloomFilter_RealTxids(t *testing.T) {
	partitiontest.PartitionTest(t)

	filter := createFastTXIDBloomFilter(10)

	// Create transaction IDs using crypto.Digest (which is what Txid is)
	txids := make([]transactions.Txid, 5)
	for i := 0; i < len(txids); i++ {
		// Create a digest from random data
		var data [32]byte
		_, err := rand.Read(data[:])
		require.NoError(t, err)
		digest := crypto.Hash(data[:])
		txids[i] = transactions.Txid(digest)
	}

	// Add all transaction IDs
	for _, txid := range txids {
		filter.Add(txid)
	}

	// Verify all are found
	for i, txid := range txids {
		require.True(t, filter.Test(txid), "Real transaction ID %d should be found", i)
	}
}

// BenchmarkFastTXIDBloomFilter_Add benchmarks the Add operation
func BenchmarkFastTXIDBloomFilter_Add(b *testing.B) {
	filter := createFastTXIDBloomFilter(10000)

	var txid transactions.Txid
	_, _ = rand.Read(txid[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Modify txid slightly for each iteration
		txid[0] = byte(i)
		filter.Add(txid)
	}
}

// BenchmarkFastTXIDBloomFilter_Test benchmarks the Test operation
func BenchmarkFastTXIDBloomFilter_Test(b *testing.B) {
	filter := createFastTXIDBloomFilter(10000)

	var txid transactions.Txid
	_, _ = rand.Read(txid[:])
	filter.Add(txid)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filter.Test(txid)
	}
}

// BenchmarkFastTXIDBloomFilter_AddAndTest benchmarks combined Add and Test operations
func BenchmarkFastTXIDBloomFilter_AddAndTest(b *testing.B) {
	filter := createFastTXIDBloomFilter(10000)

	var txid transactions.Txid
	_, _ = rand.Read(txid[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		txid[0] = byte(i)
		filter.Add(txid)
		_ = filter.Test(txid)
	}
}
