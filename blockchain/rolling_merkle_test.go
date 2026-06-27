package blockchain

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

func TestRollingMerkleAdd(t *testing.T) {
	tests := []struct {
		leaves            []chainhash.Hash
		expectedRoots     []chainhash.Hash
		expectedNumLeaves uint64
	}{
		// 00  (00 is also a root)
		{
			leaves: []chainhash.Hash{
				{0x00},
			},
			expectedRoots: []chainhash.Hash{
				{0x00},
			},
			expectedNumLeaves: 1,
		},

		// root
		// |---\
		// 00  01
		{
			leaves: []chainhash.Hash{
				{0x00},
				{0x01},
			},
			expectedRoots: []chainhash.Hash{
				func() chainhash.Hash {
					hash, err := chainhash.NewHashFromStr(
						"f7503264ea3c4727" +
							"e0e67fec5e6f67f7" +
							"af361f5659d7db05" +
							"f1061293096fbfcd")
					require.NoError(t, err)
					return *hash
				}(),
			},
			expectedNumLeaves: 2,
		},

		// root
		// |---\
		// 00  01  02
		{
			leaves: []chainhash.Hash{
				{0x00},
				{0x01},
				{0x02},
			},
			expectedRoots: []chainhash.Hash{
				func() chainhash.Hash {
					hash, err := chainhash.NewHashFromStr(
						"f7503264ea3c4727" +
							"e0e67fec5e6f67f7" +
							"af361f5659d7db05" +
							"f1061293096fbfcd")
					require.NoError(t, err)
					return *hash
				}(),
				{0x02},
			},
			expectedNumLeaves: 3,
		},

		// root
		// |-------\
		// br      br
		// |---\   |---\
		// 00  01  02  03
		{
			leaves: []chainhash.Hash{
				{0x00},
				{0x01},
				{0x02},
				{0x03},
			},
			expectedRoots: []chainhash.Hash{
				func() chainhash.Hash {
					hash, err := chainhash.NewHashFromStr(
						"64984cf29e322ded" +
							"31951dc614fe3a20" +
							"a0fc19fb893cced6" +
							"adad9d6153eaceaa")
					require.NoError(t, err)
					return *hash
				}(),
			},
			expectedNumLeaves: 4,
		},

		// root
		// |-------\
		// br      br
		// |---\   |---\
		// 00  01  02  03  04
		{
			leaves: []chainhash.Hash{
				{0x00},
				{0x01},
				{0x02},
				{0x03},
				{0x04},
			},
			expectedRoots: []chainhash.Hash{
				func() chainhash.Hash {
					hash, err := chainhash.NewHashFromStr(
						"64984cf29e322ded" +
							"31951dc614fe3a20" +
							"a0fc19fb893cced6" +
							"adad9d6153eaceaa")
					require.NoError(t, err)
					return *hash
				}(),
				{0x04},
			},
			expectedNumLeaves: 5,
		},

		// root
		// |-------\
		// br      br      root
		// |---\   |---\   |---\
		// 00  01  02  03  04  05
		{
			leaves: []chainhash.Hash{
				{0x00},
				{0x01},
				{0x02},
				{0x03},
				{0x04},
				{0x05},
			},
			expectedRoots: []chainhash.Hash{
				func() chainhash.Hash {
					hash, err := chainhash.NewHashFromStr(
						"64984cf29e322ded" +
							"31951dc614fe3a20" +
							"a0fc19fb893cced6" +
							"adad9d6153eaceaa")
					require.NoError(t, err)
					return *hash
				}(),
				func() chainhash.Hash {
					hash, err := chainhash.NewHashFromStr(
						"9b1b078538375501" +
							"da88684001a6f171" +
							"598407aa420c94ff" +
							"84dc155d68c650cd")
					require.NoError(t, err)
					return *hash
				}(),
			},
			expectedNumLeaves: 6,
		},
	}

	for _, test := range tests {
		s := newRollingMerkleTreeStore(uint64(len(test.leaves)))
		for _, leaf := range test.leaves {
			s.add(leaf)
		}

		require.Equal(t, s.roots, test.expectedRoots)
		require.Equal(t, s.numLeaves, test.expectedNumLeaves)
	}
}
