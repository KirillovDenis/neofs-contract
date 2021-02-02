package reputationcontract

import (
	"github.com/nspcc-dev/neo-go/pkg/interop/runtime"
	"github.com/nspcc-dev/neo-go/pkg/interop/storage"
	"github.com/nspcc-dev/neofs-contract/common"
)

const version = 1

const (
	peerIDSize   = 46 // NeoFS PeerIDSize
	trustValSize = 8  // float64

	trustStructSize = 0 +
		peerIDSize + // manager ID
		peerIDSize + // trusted ID
		trustValSize // trust value
)

var (
	trustJournalPrefix = []byte("trustJournal")

	ctx storage.Context
)

func init() {
	if runtime.GetTrigger() != runtime.Application {
		panic("contract has not been called in application node")
	}

	ctx = storage.GetContext()
}

func Put(manager, epoch, typ []byte, newTrustList [][]byte) bool {
	if !runtime.CheckWitness(manager) {
		panic("put: incorrect manager key")
	}

	for i := 0; i < len(newTrustList); i++ {
		trustData := newTrustList[i]

		if len(trustData) != trustStructSize {
			panic("list: invalid trust value")
		}
	}

	// todo: consider using notification for inner ring node

	// todo: limit size of the trust journal:
	//       history will be stored in chain (args or notifies)
	//       contract storage will be used as a cache if needed
	key := append(trustJournalPrefix, append(epoch, typ...)...)

	trustList := common.GetList(ctx, key)

	// fixme: with neo3.0 it is kinda unnecessary
	if len(trustList) == 0 {
		// if journal slice is not initialized, then `append` will throw
		trustList = newTrustList
	} else {
		for i := 0; i < len(newTrustList); i++ {
			trustList = append(trustList, newTrustList[i])
		}
	}

	common.SetSerialized(ctx, key, trustList)

	runtime.Log("trust list was successfully updated")

	return true
}

func List(epoch, typ []byte) [][]byte {
	key := append(trustJournalPrefix, append(epoch, typ...)...)

	return common.GetList(ctx, key)
}
