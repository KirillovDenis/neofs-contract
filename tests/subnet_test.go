package tests

import (
	"encoding/binary"
	"path"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/neotest"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/vm"
	"github.com/nspcc-dev/neo-go/pkg/vm/stackitem"
	"github.com/nspcc-dev/neofs-contract/common"
	"github.com/nspcc-dev/neofs-contract/subnet"
	"github.com/stretchr/testify/require"
)

const subnetPath = "../subnet"

func deploySubnetContract(t *testing.T, e *neotest.Executor) util.Uint160 {
	c := neotest.CompileFile(t, e.CommitteeHash, subnetPath, path.Join(subnetPath, "config.yml"))
	args := []interface{}{false}
	e.DeployContract(t, c, args)
	return c.Hash
}

func newSubnetInvoker(t *testing.T) *neotest.ContractInvoker {
	e := newExecutor(t)
	h := deploySubnetContract(t, e)
	return e.CommitteeInvoker(h)
}

func TestSubnet_Version(t *testing.T) {
	e := newSubnetInvoker(t)
	e.Invoke(t, common.Version, "version")
}

func TestSubnet_Put(t *testing.T) {
	e := newSubnetInvoker(t)

	acc := e.NewAccount(t)
	pub, ok := vm.ParseSignatureContract(acc.Script())
	require.True(t, ok)

	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, 123)
	info := randomBytes(10)

	e.InvokeFail(t, "witness check failed", "put", id, pub, info)

	cAcc := e.WithSigners(acc)
	cAcc.InvokeFail(t, "alphabet witness check failed", "put", id, pub, info)

	cBoth := e.WithSigners(e.Committee, acc)
	cBoth.InvokeFail(t, subnet.ErrInvalidSubnetID, "put", []byte{1, 2, 3}, pub, info)
	cBoth.InvokeFail(t, subnet.ErrInvalidOwner, "put", id, pub[10:], info)
	cBoth.Invoke(t, stackitem.Null{}, "put", id, pub, info)
	cAcc.Invoke(t, stackitem.NewBuffer(info), "get", id)
	cBoth.InvokeFail(t, subnet.ErrAlreadyExists, "put", id, pub, info)
}

func TestSubnet_Delete(t *testing.T) {
	e := newSubnetInvoker(t)

	acc := e.NewAccount(t)
	pub, ok := vm.ParseSignatureContract(acc.Script())
	require.True(t, ok)

	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, 123)
	info := randomBytes(10)

	cBoth := e.WithSigners(e.Committee, acc)
	cBoth.Invoke(t, stackitem.Null{}, "put", id, pub, info)

	e.InvokeFail(t, "witness check failed", "delete", id)

	cAcc := e.WithSigners(acc)
	cAcc.InvokeFail(t, subnet.ErrNotExist, "delete", []byte{1, 1, 1, 1})
	cAcc.Invoke(t, stackitem.Null{}, "delete", id)
	cAcc.InvokeFail(t, subnet.ErrNotExist, "get", id)
	cAcc.InvokeFail(t, subnet.ErrNotExist, "delete", id)
}

func TestSubnet_AddNodeAdmin(t *testing.T) {
	e := newSubnetInvoker(t)

	owner := e.NewAccount(t)
	pub, ok := vm.ParseSignatureContract(owner.Script())
	require.True(t, ok)

	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, 123)
	info := randomBytes(10)

	cBoth := e.WithSigners(e.Committee, owner)
	cBoth.Invoke(t, stackitem.Null{}, "put", id, pub, info)

	adm := e.NewAccount(t)
	admPub, ok := vm.ParseSignatureContract(adm.Script())
	require.True(t, ok)

	const (
		method       = "addNodeAdmin"
		errSeparator = ": "
	)

	e.InvokeFail(t, method+errSeparator+subnet.ErrInvalidAdmin, method, id, admPub[1:])
	e.InvokeFail(t, method+errSeparator+subnet.ErrNotExist, method, []byte{0, 0, 0, 0}, admPub)

	cAdm := e.WithSigners(adm)
	cAdm.InvokeFail(t, method+errSeparator+"owner witness check failed", method, id, admPub)

	cOwner := e.WithSigners(owner)
	cOwner.Invoke(t, stackitem.Null{}, method, id, admPub)

	cOwner.InvokeFail(t, method+errSeparator+"node admin has already been added", method, id, admPub)
}