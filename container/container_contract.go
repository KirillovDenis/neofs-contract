package container

import (
	"github.com/nspcc-dev/neo-go/pkg/interop"
	"github.com/nspcc-dev/neo-go/pkg/interop/contract"
	"github.com/nspcc-dev/neo-go/pkg/interop/convert"
	"github.com/nspcc-dev/neo-go/pkg/interop/iterator"
	"github.com/nspcc-dev/neo-go/pkg/interop/native/crypto"
	"github.com/nspcc-dev/neo-go/pkg/interop/native/management"
	"github.com/nspcc-dev/neo-go/pkg/interop/native/std"
	"github.com/nspcc-dev/neo-go/pkg/interop/runtime"
	"github.com/nspcc-dev/neo-go/pkg/interop/storage"
	"github.com/nspcc-dev/neofs-contract/common"
)

type (
	storageNode struct {
		info []byte
	}

	Container struct {
		value []byte
		sig   interop.Signature
		pub   interop.PublicKey
		token []byte
	}

	ExtendedACL struct {
		value []byte
		sig   interop.Signature
		pub   interop.PublicKey
		token []byte
	}

	ExtendedACLChunks struct {
		containerID []byte
		version     []byte
	}

	Ruleset struct {
		id      int
		prev    int
		next    int
		records []byte
	}

	estimation struct {
		from interop.PublicKey
		size int
	}

	containerSizes struct {
		cid         []byte
		estimations []estimation
	}
)

const (
	neofsIDContractKey = "identityScriptHash"
	balanceContractKey = "balanceScriptHash"
	netmapContractKey  = "netmapScriptHash"
	nnsContractKey     = "nnsScriptHash"
	nnsRootKey         = "nnsRoot"
	nnsHasAliasKey     = "nnsHasAlias"
	notaryDisabledKey  = "notary"

	counterPrefixKey byte = 'i'
	rulesetKey            = "ruleset"

	// RegistrationFeeKey is a key in netmap config which contains fee for container registration.
	RegistrationFeeKey = "ContainerFee"
	// AliasFeeKey is a key in netmap config which contains fee for nice-name registration.
	AliasFeeKey = "ContainerAliasFee"

	// V2 format
	containerIDSize = 32 // SHA256 size

	singleEstimatePrefix = "est"
	estimateKeyPrefix    = "cnr"
	estimatePostfixSize  = 10
	// CleanupDelta contains the number of the last epochs for which container estimations are present.
	CleanupDelta = 3
	// TotalCleanupDelta contains the number of the epochs after which estimation
	// will be removed by epoch tick cleanup if any of the nodes hasn't updated
	// container size and/or container has been removed. It must be greater than CleanupDelta.
	TotalCleanupDelta = CleanupDelta + 1

	// NotFoundError is returned if container is missing.
	NotFoundError = "container does not exist"

	// default SOA record field values
	defaultRefresh = 3600   // 1 hour
	defaultRetry   = 600    // 10 min
	defaultExpire  = 604800 // 1 week
	defaultTTL     = 3600   // 1 hour
)

var (
	eACLPrefix = []byte("eACL")

	eACLChunkPrefix = []byte("eACLChunk")
)

// OnNEP11Payment is needed for registration with contract as the owner to work.
func OnNEP11Payment(a interop.Hash160, b int, c []byte, d interface{}) {
}

func _deploy(data interface{}, isUpdate bool) {
	ctx := storage.GetContext()
	if isUpdate {
		args := data.([]interface{})
		common.CheckVersion(args[len(args)-1].(int))
		return
	}

	args := data.(struct {
		notaryDisabled bool
		addrNetmap     interop.Hash160
		addrBalance    interop.Hash160
		addrID         interop.Hash160
		addrNNS        interop.Hash160
		nnsRoot        string
	})

	if len(args.addrNetmap) != interop.Hash160Len ||
		len(args.addrBalance) != interop.Hash160Len ||
		len(args.addrID) != interop.Hash160Len {
		panic("incorrect length of contract script hash")
	}

	storage.Put(ctx, netmapContractKey, args.addrNetmap)
	storage.Put(ctx, balanceContractKey, args.addrBalance)
	storage.Put(ctx, neofsIDContractKey, args.addrID)
	storage.Put(ctx, nnsContractKey, args.addrNNS)
	storage.Put(ctx, nnsRootKey, args.nnsRoot)

	// initialize the way to collect signatures
	storage.Put(ctx, notaryDisabledKey, args.notaryDisabled)
	if args.notaryDisabled {
		common.InitVote(ctx)
		runtime.Log("container contract notary disabled")
	}

	// add NNS root for container alias domains
	registerNiceNameTLD(args.addrNNS, args.nnsRoot)

	runtime.Log("container contract initialized")
}

func registerNiceNameTLD(addrNNS interop.Hash160, nnsRoot string) {
	isAvail := contract.Call(addrNNS, "isAvailable", contract.AllowCall|contract.ReadStates,
		"container").(bool)
	if !isAvail {
		return
	}

	res := contract.Call(addrNNS, "register", contract.All,
		nnsRoot, runtime.GetExecutingScriptHash(), "ops@nspcc.ru",
		defaultRefresh, defaultRetry, defaultExpire, defaultTTL).(bool)
	if !res {
		panic("can't register NNS TLD")
	}
}

// Update method updates contract source code and manifest. It can be invoked
// by committee only.
func Update(script []byte, manifest []byte, data interface{}) {
	if !common.HasUpdateAccess() {
		panic("only committee can update contract")
	}

	contract.Call(interop.Hash160(management.Hash), "update",
		contract.All, script, manifest, common.AppendVersion(data))
	runtime.Log("container contract updated")
}

// Put method creates a new container if it has been invoked by Alphabet nodes
// of the Inner Ring. Otherwise, it produces containerPut notification.
//
// Container should be a stable marshaled Container structure from API.
// Signature is a RFC6979 signature of the Container.
// PublicKey contains the public key of the signer.
// Token is optional and should be a stable marshaled SessionToken structure from
// API.
func Put(container []byte, signature interop.Signature, publicKey interop.PublicKey, token []byte) {
	PutNamed(container, signature, publicKey, token, "", "")
}

// PutNamed is similar to put but also sets a TXT record in nns contract.
// Note that zone must exist.
func PutNamed(container []byte, signature interop.Signature,
	publicKey interop.PublicKey, token []byte,
	name, zone string) {
	ctx := storage.GetContext()
	notaryDisabled := storage.Get(ctx, notaryDisabledKey).(bool)

	ownerID := ownerFromBinaryContainer(container)
	containerID := crypto.Sha256(container)
	neofsIDContractAddr := storage.Get(ctx, neofsIDContractKey).(interop.Hash160)
	cnr := Container{
		value: container,
		sig:   signature,
		pub:   publicKey,
		token: token,
	}

	var (
		needRegister    bool
		nnsContractAddr interop.Hash160
		domain          string
	)
	if name != "" {
		if zone == "" {
			zone = storage.Get(ctx, nnsRootKey).(string)
		}
		nnsContractAddr = storage.Get(ctx, nnsContractKey).(interop.Hash160)
		domain = name + "." + zone
		needRegister = checkNiceNameAvailable(nnsContractAddr, domain)
	}

	alphabet := common.AlphabetNodes()
	from := common.WalletToScriptHash(ownerID)
	netmapContractAddr := storage.Get(ctx, netmapContractKey).(interop.Hash160)
	balanceContractAddr := storage.Get(ctx, balanceContractKey).(interop.Hash160)
	containerFee := contract.Call(netmapContractAddr, "config", contract.ReadOnly, RegistrationFeeKey).(int)
	balance := contract.Call(balanceContractAddr, "balanceOf", contract.ReadOnly, from).(int)
	if name != "" {
		aliasFee := contract.Call(netmapContractAddr, "config", contract.ReadOnly, AliasFeeKey).(int)
		containerFee += aliasFee
	}

	if balance < containerFee*len(alphabet) {
		panic("insufficient balance to create container")
	}

	if notaryDisabled {
		nodeKey := common.InnerRingInvoker(alphabet)
		if len(nodeKey) == 0 {
			runtime.Notify("containerPut", container, signature, publicKey, token)
			return
		}

		threshold := len(alphabet)*2/3 + 1
		id := common.InvokeID([]interface{}{container, signature, publicKey}, []byte("put"))

		n := common.Vote(ctx, id, nodeKey)
		if n < threshold {
			return
		}

		common.RemoveVotes(ctx, id)
	} else {
		multiaddr := common.AlphabetAddress()
		common.CheckAlphabetWitness(multiaddr)
	}
	// todo: check if new container with unique container id

	details := common.ContainerFeeTransferDetails(containerID)

	for i := 0; i < len(alphabet); i++ {
		node := alphabet[i]
		to := contract.CreateStandardAccount(node)

		contract.Call(balanceContractAddr, "transferX",
			contract.All,
			from,
			to,
			containerFee,
			details,
		)
	}

	addContainer(ctx, containerID, ownerID, cnr)

	if name != "" {
		if needRegister {
			res := contract.Call(nnsContractAddr, "register", contract.All,
				domain, runtime.GetExecutingScriptHash(), "ops@nspcc.ru",
				defaultRefresh, defaultRetry, defaultExpire, defaultTTL).(bool)
			if !res {
				panic("can't register the domain " + domain)
			}
		}
		contract.Call(nnsContractAddr, "addRecord", contract.All,
			domain, 16 /* TXT */, std.Base58Encode(containerID))

		key := append([]byte(nnsHasAliasKey), containerID...)
		storage.Put(ctx, key, domain)
	}

	if len(token) == 0 { // if container created directly without session
		contract.Call(neofsIDContractAddr, "addKey", contract.All, ownerID, [][]byte{publicKey})
	}

	runtime.Log("added new container")
	runtime.Notify("PutSuccess", containerID, publicKey)
}

// checkNiceNameAvailable checks if the nice name is available for the container.
// It panics if the name is taken. Returned value specifies if new domain registration is needed.
func checkNiceNameAvailable(nnsContractAddr interop.Hash160, domain string) bool {
	isAvail := contract.Call(nnsContractAddr, "isAvailable",
		contract.ReadStates|contract.AllowCall, domain).(bool)
	if isAvail {
		return true
	}

	owner := contract.Call(nnsContractAddr, "ownerOf",
		contract.ReadStates|contract.AllowCall, domain).(string)
	if owner != string(common.CommitteeAddress()) && owner != string(runtime.GetExecutingScriptHash()) {
		panic("committee or container contract must own registered domain")
	}

	res := contract.Call(nnsContractAddr, "getRecords",
		contract.ReadStates|contract.AllowCall, domain, 16 /* TXT */)
	if res != nil {
		panic("name is already taken")
	}

	return false
}

// Delete method removes a container from the contract storage if it has been
// invoked by Alphabet nodes of the Inner Ring. Otherwise, it produces
// containerDelete notification.
//
// Signature is a RFC6979 signature of the container ID.
// Token is optional and should be a stable marshaled SessionToken structure from
// API.
//
// If the container doesn't exist, it panics with NotFoundError.
func Delete(containerID []byte, signature interop.Signature, token []byte) {
	ctx := storage.GetContext()
	notaryDisabled := storage.Get(ctx, notaryDisabledKey).(bool)

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		return
	}

	if notaryDisabled {
		alphabet := common.AlphabetNodes()
		nodeKey := common.InnerRingInvoker(alphabet)
		if len(nodeKey) == 0 {
			runtime.Notify("containerDelete", containerID, signature, token)
			return
		}

		threshold := len(alphabet)*2/3 + 1
		id := common.InvokeID([]interface{}{containerID, signature}, []byte("delete"))

		n := common.Vote(ctx, id, nodeKey)
		if n < threshold {
			return
		}

		common.RemoveVotes(ctx, id)
	} else {
		multiaddr := common.AlphabetAddress()
		common.CheckAlphabetWitness(multiaddr)
	}

	key := append([]byte(nnsHasAliasKey), containerID...)
	domain := storage.Get(ctx, key).(string)
	if len(domain) != 0 {
		storage.Delete(ctx, key)
		// We should do `getRecord` first because NNS record could be deleted
		// by other means (expiration, manual), thus leading to failing `deleteRecord`
		// and inability to delete a container. We should also check if we own the record in case.
		nnsContractAddr := storage.Get(ctx, nnsContractKey).(interop.Hash160)
		res := contract.Call(nnsContractAddr, "getRecords", contract.ReadStates|contract.AllowCall, domain, 16 /* TXT */)
		if res != nil && std.Base58Encode(containerID) == string(res.([]interface{})[0].(string)) {
			contract.Call(nnsContractAddr, "deleteRecords", contract.All, domain, 16 /* TXT */)
		}
	}
	removeContainer(ctx, containerID, ownerID)
	runtime.Log("remove container")
	runtime.Notify("DeleteSuccess", containerID)
}

// Get method returns a structure that contains a stable marshaled Container structure,
// the signature, the public key of the container creator and a stable marshaled SessionToken
// structure if it was provided.
//
// If the container doesn't exist, it panics with NotFoundError.
func Get(containerID []byte) Container {
	ctx := storage.GetReadOnlyContext()
	cnt := getContainer(ctx, containerID)
	if len(cnt.value) == 0 {
		panic(NotFoundError)
	}
	return cnt
}

// Owner method returns a 25 byte Owner ID of the container.
//
// If the container doesn't exist, it panics with NotFoundError.
func Owner(containerID []byte) []byte {
	ctx := storage.GetReadOnlyContext()
	owner := getOwnerByID(ctx, containerID)
	if owner == nil {
		panic(NotFoundError)
	}
	return owner
}

// Count method returns the number of registered containers.
func Count() int {
	count := 0
	ctx := storage.GetReadOnlyContext()
	it := storage.Find(ctx, []byte{}, storage.KeysOnly)
	for iterator.Next(it) {
		key := iterator.Value(it).([]byte)
		// V2 format
		if len(key) == containerIDSize {
			count++
		}
	}
	return count
}

// List method returns a list of all container IDs owned by the specified owner.
func List(owner []byte) [][]byte {
	ctx := storage.GetReadOnlyContext()

	if len(owner) == 0 {
		return getAllContainers(ctx)
	}

	var list [][]byte

	it := storage.Find(ctx, owner, storage.ValuesOnly)
	for iterator.Next(it) {
		id := iterator.Value(it).([]byte)
		list = append(list, id)
	}

	return list
}

// SetEACL method sets a new extended ACL table related to the contract
// if it was invoked by Alphabet nodes of the Inner Ring. Otherwise, it produces
// setEACL notification.
//
// EACL should be a stable marshaled EACLTable structure from API.
// Signature is a RFC6979 signature of the Container.
// PublicKey contains the public key of the signer.
// Token is optional and should be a stable marshaled SessionToken structure from
// API.
//
// If the container doesn't exist, it panics with NotFoundError.
func SetEACL(eACL []byte, signature interop.Signature, publicKey interop.PublicKey, token []byte) {
	ctx := storage.GetContext()
	notaryDisabled := storage.Get(ctx, notaryDisabledKey).(bool)

	// V2 format
	// get container ID
	offset := int(eACL[1])
	offset = 2 + offset + 4
	containerID := eACL[offset : offset+32]

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	if notaryDisabled {
		alphabet := common.AlphabetNodes()
		nodeKey := common.InnerRingInvoker(alphabet)
		if len(nodeKey) == 0 {
			runtime.Notify("setEACL", eACL, signature, publicKey, token)
			return
		}

		threshold := len(alphabet)*2/3 + 1
		id := common.InvokeID([]interface{}{eACL}, []byte("setEACL"))

		n := common.Vote(ctx, id, nodeKey)
		if n < threshold {
			return
		}

		common.RemoveVotes(ctx, id)
	} else {
		multiaddr := common.AlphabetAddress()
		common.CheckAlphabetWitness(multiaddr)
	}

	rule := ExtendedACL{
		value: eACL,
		sig:   signature,
		pub:   publicKey,
		token: token,
	}

	key := append(eACLPrefix, containerID...)

	common.SetSerialized(ctx, key, rule)

	runtime.Log("success")
	runtime.Notify("SetEACLSuccess", containerID, publicKey)
}

// InsertEACLRuleset append EACL ruleset to the specific position in ruleset list.
// ContainerID is 32 byte hash. VersionStrut is protobuf encoded version.
func InsertEACLRuleset(containerID []byte, versionStruct []byte, prev, next int, data []byte) int {
	ctx := storage.GetContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	createTableIfNotExist(ctx, containerID, versionStruct)
	return insertRuleset(ctx, containerID, prev, next, data)
}

// AppendEACLRuleset append EACL ruleset to the end of ruleset list.
// ContainerID is 32 byte hash. VersionStrut is protobuf encoded version.
// Data is a stable marshaled eacl records.
func AppendEACLRuleset(containerID []byte, versionStruct []byte, data []byte) int {
	ctx := storage.GetContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	createTableIfNotExist(ctx, containerID, versionStruct)

	tail := findLinkedItem(ctx, containerID, false)
	if tail == 0 {
		return insertRuleset(ctx, containerID, 0, 0, data)
	}

	return insertRuleset(ctx, containerID, tail, 0, data)
}

func PrependEACLRuleset(containerID []byte, versionStruct []byte, data []byte) int {
	ctx := storage.GetContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	createTableIfNotExist(ctx, containerID, versionStruct)

	head := findLinkedItem(ctx, containerID, true)
	if head == 0 {
		return insertRuleset(ctx, containerID, 0, 0, data)
	}

	return insertRuleset(ctx, containerID, 0, head, data)
}

func ReplaceEACLRuleset(containerID []byte, id int, data []byte) {
	ctx := storage.GetContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	getTableInfo(ctx, containerID) // check table existence

	key := formRulesetKey(containerID, id)
	ruleset := getRuleset(ctx, key)
	ruleset.records = data

	common.SetSerialized(ctx, key, ruleset)
}

func DeleteEACLRuleset(containerID []byte, id int) {
	ctx := storage.GetContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	getTableInfo(ctx, containerID) // check table existence

	key := formRulesetKey(containerID, id)
	ruleset := getRuleset(ctx, key)

	if ruleset.prev > 0 {
		prevKey := formRulesetKey(containerID, ruleset.prev)
		prevRuleset := getRuleset(ctx, prevKey)
		prevRuleset.next = ruleset.next
		common.SetSerialized(ctx, prevKey, prevRuleset)
	}

	if ruleset.next > 0 {
		nextKey := formRulesetKey(containerID, ruleset.next)
		nextRuleset := getRuleset(ctx, nextKey)
		nextRuleset.prev = ruleset.prev
		common.SetSerialized(ctx, nextKey, nextRuleset)
	}

	storage.Delete(ctx, key)
}

func createTableIfNotExist(ctx storage.Context, containerID, versionStruct []byte) {
	tableKey := append(eACLChunkPrefix, containerID...)
	tableBytes := storage.Get(ctx, tableKey).([]byte)
	if tableBytes == nil {
		table := ExtendedACLChunks{
			containerID: containerID,
			version:     versionStruct,
		}
		common.SetSerialized(ctx, tableKey, table)
	}
}

func getTableInfo(ctx storage.Context, containerID []byte) ExtendedACLChunks {
	tableKey := append(eACLChunkPrefix, containerID...)
	tableBytes := storage.Get(ctx, tableKey).([]byte)
	if tableBytes == nil {
		panic("table doesn't exist")
	}

	return std.Deserialize(tableBytes).(ExtendedACLChunks)
}

func insertRuleset(ctx storage.Context, containerID []byte, prev, next int, data []byte) int {
	if prev == 0 && next == 0 && countRulesets(ctx, containerID) != 0 {
		panic("invalid ruleset position")
	}

	rulesetCounter := updateCounter(ctx, containerID)

	if prev > 0 {
		updateLinkedItem(ctx, containerID, prev, false, rulesetCounter)
	}
	if next > 0 {
		updateLinkedItem(ctx, containerID, next, true, rulesetCounter)
	}

	putRuleset(ctx, containerID, rulesetCounter, prev, next, data)

	return rulesetCounter
}

func countRulesets(ctx storage.Context, containerID []byte) int {
	prefix := append([]byte(rulesetKey), containerID...)
	it := storage.Find(ctx, prefix, storage.KeysOnly)

	count := 0
	for iterator.Next(it) {
		count++
	}

	return count
}

func putRuleset(ctx storage.Context, containerID []byte, id, prev, next int, data []byte) {
	key := formRulesetKey(containerID, id)
	ruleSet := Ruleset{
		id:      id,
		prev:    prev,
		next:    next,
		records: data,
	}
	common.SetSerialized(ctx, key, ruleSet)
}

func getRuleset(ctx storage.Context, key []byte) Ruleset {
	rulesetBytes := storage.Get(ctx, key).([]byte)
	if rulesetBytes == nil {
		panic("not found ruleset")
	}

	return std.Deserialize(rulesetBytes).(Ruleset)
}

func updateCounter(ctx storage.Context, containerID []byte) int {
	counterKey := append([]byte{counterPrefixKey}, containerID...)
	raw := storage.Get(ctx, counterKey)
	rulesetCounter := 0
	if raw != nil {
		rulesetCounter = raw.(int)
	}
	rulesetCounter++
	storage.Put(ctx, counterKey, rulesetCounter)

	return rulesetCounter
}

func formRulesetKey(containerID []byte, id int) []byte {
	counterBytes := std.Serialize(id)
	return append([]byte(rulesetKey), append(containerID, counterBytes...)...)
}

func updateLinkedItem(ctx storage.Context, containerID []byte, id int, setPrev bool, val int) {
	key := formRulesetKey(containerID, id)
	rulesetBytes := storage.Get(ctx, key).([]byte)
	if rulesetBytes == nil {
		panic("invalid ruleset id")
	}

	prevRuleset := std.Deserialize(rulesetBytes).(Ruleset)
	if setPrev {
		prevRuleset.prev = val
	} else {
		prevRuleset.next = val
	}
	common.SetSerialized(ctx, key, prevRuleset)
}

// findLinkedItem looks for head or tail id in rulesets list. If no item is found then returns 0.
// We use 0 instead of -1 as no link to prev item for head or next item for tail because using negative
// number require much more bytes https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
// (we don't use "ZigZag" encoding).
func findLinkedItem(ctx storage.Context, containerID []byte, needHead bool) int {
	prefix := append([]byte(rulesetKey), containerID...)
	it := storage.Find(ctx, prefix, storage.ValuesOnly|storage.DeserializeValues)
	for iterator.Next(it) {
		rs := iterator.Value(it).(Ruleset)

		if rs.prev == 0 && needHead ||
			rs.next == 0 && !needHead {
			return rs.id
		}
	}

	return 0
}

// EACL method returns a structure that contains a stable marshaled EACLTable structure,
// the signature, the public key of the extended ACL setter and a stable marshaled SessionToken
// structure if it was provided.
//
// If the container doesn't exist, it panics with NotFoundError.
func EACL(containerID []byte) ExtendedACL {
	ctx := storage.GetReadOnlyContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	return getEACL(ctx, containerID)
}

func EACLChunked(containerID []byte) ExtendedACL {
	ctx := storage.GetReadOnlyContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	table := getTableInfo(ctx, containerID)
	rulesets := EACLRulesets(containerID)

	eaclTable := mergeChunksToTable(table, rulesets)

	return ExtendedACL{
		value: eaclTable,
		sig:   interop.Signature{},
		pub:   interop.PublicKey{},
		token: []byte{},
	}
}

func EACLRulesets(containerID []byte) []Ruleset {
	ctx := storage.GetReadOnlyContext()

	ownerID := getOwnerByID(ctx, containerID)
	if ownerID == nil {
		panic(NotFoundError)
	}

	rulesetMap := make(map[int]Ruleset)
	nextID := 0

	prefix := append([]byte(rulesetKey), containerID...)
	it := storage.Find(ctx, prefix, storage.ValuesOnly|storage.DeserializeValues)
	for iterator.Next(it) {
		rs := iterator.Value(it).(Ruleset)
		rulesetMap[rs.id] = rs
		if rs.prev == 0 {
			nextID = rs.id
		}
	}

	if nextID == 0 && len(rulesetMap) > 0 {
		panic("invalid linked ruleset list")
	}

	result := []Ruleset{}
	var rs Ruleset
	for nextID > 0 {
		rs = rulesetMap[nextID]
		result = append(result, rs)
		nextID = rs.next
	}

	return result
}

const (
	tableVersionField   = 1
	tableContainerField = 2
	tableRecordsField   = 3

	containerIDField = 1
)

// assume cnrID and version are encoded
func mergeChunksToTable(eaclChunkTable ExtendedACLChunks, rulesets []Ruleset) []byte {
	encodedVersion := encodeVersion(eaclChunkTable.version)
	encodedCnrID := encodeContainerID(eaclChunkTable.containerID)

	result := append(encodedVersion, encodedCnrID...)

	recordPrefix := tableRecordsField<<3 | 0x02
	for i := range rulesets {
		chunkRecs := rulesets[i].records
		if len(chunkRecs) < 2 {
			continue
		}

		result = append(result, byte(recordPrefix))
		result = append(result, chunkRecs[1:]...)
	}

	return result
}

func encodeVersion(version []byte) []byte {
	versionLen := uint64(len(version))
	versionBuffer := make([]byte, 1+varUIntSize(versionLen)+len(version))

	versionBuffer[0] = tableVersionField<<3 | 0x02
	versionOffset := putUvarint(versionBuffer, 1, versionLen) + 1

	copy(versionBuffer[versionOffset:], version)

	return versionBuffer
}

func encodeContainerID(cnrID []byte) []byte {
	cnrIDLen := uint64(len(cnrID))
	cnrIDBufferSize := 1 + varUIntSize(cnrIDLen) + len(cnrID)
	cnrIDStructLen := uint64(cnrIDBufferSize)
	cnrIDStructBufferSize := 1 + varUIntSize(cnrIDStructLen) + cnrIDBufferSize

	cnrIDStructBuffer := make([]byte, cnrIDStructBufferSize)

	cnrIDStructBuffer[0] = tableContainerField<<3 | 0x02
	cnrIDStructOffset := putUvarint(cnrIDStructBuffer, 1, cnrIDStructLen) + 1

	cnrIDStructBuffer[cnrIDStructOffset] = containerIDField<<3 | 0x02
	cnrIDStructOffset += putUvarint(cnrIDStructBuffer, cnrIDStructOffset+1, cnrIDLen) + 1

	copy(cnrIDStructBuffer[cnrIDStructOffset:], cnrID)

	return cnrIDStructBuffer
}

func varintOneByteFieldSize(input []byte) int {
	if len(input) < 2 || input[0]&7 != 0 { // it isn't a varint
		return 0
	}

	end := 2
	for i, b := range input[1:] {
		if b>>7 == 0 {
			end += i
			break
		}
	}

	return end
}

func varUIntSize(x uint64) int {
	return (len64(x|1) + 6) / 7
}

func putUvarint(buf []byte, index int, x uint64) int {
	i := index
	for x >= 0x80 {
		buf[i] = byte(x) | 0x80
		x = x >> 7
		i++
	}
	buf[i] = byte(x)
	return i + 1 - index
}

func encodeUvarint(x uint64) []byte {
	buf := make([]byte, varUIntSize(x))
	i := 0
	for x >= 0x80 {
		buf[i] = byte(x) | 0x80
		x = x >> 7
		i++
	}
	buf[i] = byte(x)
	return buf
}

// len64 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func len64(x uint64) int {
	var n int
	if x >= 1<<32 {
		x = x >> 32
		n = 32
	}
	if x >= 1<<16 {
		x = x >> 16
		n += 16
	}
	if x >= 1<<8 {
		x = x >> 8
		n += 8
	}

	return n + int(len8tab[x])
}

const len8tab = "" +
	"\x00\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04" +
	"\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05" +
	"\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06" +
	"\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08"

// PutContainerSize method saves container size estimation in contract
// memory. It can be invoked only by Storage nodes from the network map. This method
// checks witness based on the provided public key of the Storage node.
//
// If the container doesn't exist, it panics with NotFoundError.
func PutContainerSize(epoch int, cid []byte, usedSize int, pubKey interop.PublicKey) {
	ctx := storage.GetContext()

	if getOwnerByID(ctx, cid) == nil {
		panic(NotFoundError)
	}

	common.CheckWitness(pubKey)

	if !isStorageNode(ctx, pubKey) {
		panic("method must be invoked by storage node from network map")
	}

	key := estimationKey(epoch, cid, pubKey)

	s := estimation{
		from: pubKey,
		size: usedSize,
	}

	storage.Put(ctx, key, std.Serialize(s))
	updateEstimations(ctx, epoch, cid, pubKey, false)

	runtime.Log("saved container size estimation")
}

// GetContainerSize method returns the container ID and a slice of container
// estimations. Container estimation includes the public key of the Storage Node
// that registered estimation and value of estimation.
//
// Use the ID obtained from ListContainerSizes method. Estimations are removed
// from contract storage every epoch, see NewEpoch method; therefore, this method
// can return different results during different epochs.
func GetContainerSize(id []byte) containerSizes {
	ctx := storage.GetReadOnlyContext()

	// V2 format
	// this `id` expected to be from `ListContainerSizes`
	// therefore it is not contains postfix, we ignore it in the cut.
	ln := len(id)
	cid := id[ln-containerIDSize : ln]

	return getContainerSizeEstimation(ctx, id, cid)
}

// ListContainerSizes method returns the IDs of container size estimations
// that has been registered for the specified epoch.
func ListContainerSizes(epoch int) [][]byte {
	ctx := storage.GetReadOnlyContext()

	var buf interface{} = epoch

	key := []byte(estimateKeyPrefix)
	key = append(key, buf.([]byte)...)

	it := storage.Find(ctx, key, storage.KeysOnly)

	uniq := map[string]struct{}{}

	for iterator.Next(it) {
		storageKey := iterator.Value(it).([]byte)

		ln := len(storageKey)
		storageKey = storageKey[:ln-estimatePostfixSize]

		uniq[string(storageKey)] = struct{}{}
	}

	var result [][]byte

	for k := range uniq {
		result = append(result, []byte(k))
	}

	return result
}

// NewEpoch method removes all container size estimations from epoch older than
// epochNum + 3. It can be invoked only by NewEpoch method of the Netmap contract.
func NewEpoch(epochNum int) {
	ctx := storage.GetContext()
	notaryDisabled := storage.Get(ctx, notaryDisabledKey).(bool)

	if notaryDisabled {
		indirectCall := common.FromKnownContract(
			ctx,
			runtime.GetCallingScriptHash(),
			netmapContractKey,
		)
		if !indirectCall {
			panic("method must be invoked by inner ring")
		}
	} else {
		multiaddr := common.AlphabetAddress()
		common.CheckAlphabetWitness(multiaddr)
	}

	cleanupContainers(ctx, epochNum)
}

// StartContainerEstimation method produces StartEstimation notification.
// It can be invoked only by Alphabet nodes of the Inner Ring.
func StartContainerEstimation(epoch int) {
	ctx := storage.GetContext()
	notaryDisabled := storage.Get(ctx, notaryDisabledKey).(bool)

	var ( // for invocation collection without notary
		alphabet []interop.PublicKey
		nodeKey  []byte
	)

	if notaryDisabled {
		alphabet = common.AlphabetNodes()
		nodeKey = common.InnerRingInvoker(alphabet)
		if len(nodeKey) == 0 {
			panic("method must be invoked by inner ring")
		}
	} else {
		multiaddr := common.AlphabetAddress()
		common.CheckAlphabetWitness(multiaddr)
	}

	if notaryDisabled {
		threshold := len(alphabet)*2/3 + 1
		id := common.InvokeID([]interface{}{epoch}, []byte("startEstimation"))

		n := common.Vote(ctx, id, nodeKey)
		if n < threshold {
			return
		}

		common.RemoveVotes(ctx, id)
	}

	runtime.Notify("StartEstimation", epoch)
	runtime.Log("notification has been produced")
}

// StopContainerEstimation method produces StopEstimation notification.
// It can be invoked only by Alphabet nodes of the Inner Ring.
func StopContainerEstimation(epoch int) {
	ctx := storage.GetContext()
	notaryDisabled := storage.Get(ctx, notaryDisabledKey).(bool)

	var ( // for invocation collection without notary
		alphabet []interop.PublicKey
		nodeKey  []byte
	)

	if notaryDisabled {
		alphabet = common.AlphabetNodes()
		nodeKey = common.InnerRingInvoker(alphabet)
		if len(nodeKey) == 0 {
			panic("method must be invoked by inner ring")
		}
	} else {
		multiaddr := common.AlphabetAddress()
		common.CheckAlphabetWitness(multiaddr)
	}

	if notaryDisabled {
		threshold := len(alphabet)*2/3 + 1
		id := common.InvokeID([]interface{}{epoch}, []byte("stopEstimation"))

		n := common.Vote(ctx, id, nodeKey)
		if n < threshold {
			return
		}

		common.RemoveVotes(ctx, id)
	}

	runtime.Notify("StopEstimation", epoch)
	runtime.Log("notification has been produced")
}

// Version returns the version of the contract.
func Version() int {
	return common.Version
}

func addContainer(ctx storage.Context, id, owner []byte, container Container) {
	containerListKey := append(owner, id...)
	storage.Put(ctx, containerListKey, id)

	common.SetSerialized(ctx, id, container)
}

func removeContainer(ctx storage.Context, id []byte, owner []byte) {
	containerListKey := append(owner, id...)
	storage.Delete(ctx, containerListKey)

	storage.Delete(ctx, id)
}

func getAllContainers(ctx storage.Context) [][]byte {
	var list [][]byte

	it := storage.Find(ctx, []byte{}, storage.KeysOnly)
	for iterator.Next(it) {
		key := iterator.Value(it).([]byte) // it MUST BE `storage.KeysOnly`
		// V2 format
		if len(key) == containerIDSize {
			list = append(list, key)
		}
	}

	return list
}

func getEACL(ctx storage.Context, cid []byte) ExtendedACL {
	key := append(eACLPrefix, cid...)
	data := storage.Get(ctx, key)
	if data != nil {
		return std.Deserialize(data.([]byte)).(ExtendedACL)
	}

	return ExtendedACL{value: []byte{}, sig: interop.Signature{}, pub: interop.PublicKey{}, token: []byte{}}
}

func getContainer(ctx storage.Context, cid []byte) Container {
	data := storage.Get(ctx, cid)
	if data != nil {
		return std.Deserialize(data.([]byte)).(Container)
	}

	return Container{value: []byte{}, sig: interop.Signature{}, pub: interop.PublicKey{}, token: []byte{}}
}

func getOwnerByID(ctx storage.Context, cid []byte) []byte {
	container := getContainer(ctx, cid)
	if len(container.value) == 0 {
		return nil
	}

	return ownerFromBinaryContainer(container.value)
}

func ownerFromBinaryContainer(container []byte) []byte {
	// V2 format
	offset := int(container[1])
	offset = 2 + offset + 4              // version prefix + version size + owner prefix
	return container[offset : offset+25] // offset + size of owner
}

func estimationKey(epoch int, cid []byte, key interop.PublicKey) []byte {
	var buf interface{} = epoch

	hash := crypto.Ripemd160(key)

	result := []byte(estimateKeyPrefix)
	result = append(result, buf.([]byte)...)
	result = append(result, cid...)

	return append(result, hash[:estimatePostfixSize]...)
}

func getContainerSizeEstimation(ctx storage.Context, key, cid []byte) containerSizes {
	var estimations []estimation

	it := storage.Find(ctx, key, storage.ValuesOnly|storage.DeserializeValues)
	for iterator.Next(it) {
		est := iterator.Value(it).(estimation)
		estimations = append(estimations, est)
	}

	return containerSizes{
		cid:         cid,
		estimations: estimations,
	}
}

// isStorageNode looks into _previous_ epoch network map, because storage node
// announces container size estimation of the previous epoch.
func isStorageNode(ctx storage.Context, key interop.PublicKey) bool {
	netmapContractAddr := storage.Get(ctx, netmapContractKey).(interop.Hash160)
	snapshot := contract.Call(netmapContractAddr, "snapshot", contract.ReadOnly, 1).([]storageNode)

	for i := range snapshot {
		// V2 format
		nodeInfo := snapshot[i].info
		nodeKey := nodeInfo[2:35] // offset:2, len:33

		if common.BytesEqual(key, nodeKey) {
			return true
		}
	}

	return false
}

func updateEstimations(ctx storage.Context, epoch int, cid []byte, pub interop.PublicKey, isUpdate bool) {
	h := crypto.Ripemd160(pub)
	estKey := append([]byte(singleEstimatePrefix), cid...)
	estKey = append(estKey, h...)

	var newEpochs []int
	rawList := storage.Get(ctx, estKey).([]byte)

	if rawList != nil {
		epochs := std.Deserialize(rawList).([]int)
		for _, oldEpoch := range epochs {
			if !isUpdate && epoch-oldEpoch > CleanupDelta {
				key := append([]byte(estimateKeyPrefix), convert.ToBytes(oldEpoch)...)
				key = append(key, cid...)
				key = append(key, h[:estimatePostfixSize]...)
				storage.Delete(ctx, key)
			} else {
				newEpochs = append(newEpochs, oldEpoch)
			}
		}
	}

	newEpochs = append(newEpochs, epoch)
	common.SetSerialized(ctx, estKey, newEpochs)
}

func cleanupContainers(ctx storage.Context, epoch int) {
	it := storage.Find(ctx, []byte(estimateKeyPrefix), storage.KeysOnly)
	for iterator.Next(it) {
		k := iterator.Value(it).([]byte)
		// V2 format
		nbytes := k[len(estimateKeyPrefix) : len(k)-containerIDSize-estimatePostfixSize]

		var n interface{} = nbytes

		if epoch-n.(int) > TotalCleanupDelta {
			storage.Delete(ctx, k)
		}
	}
}
