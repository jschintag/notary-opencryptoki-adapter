package opencryptoki

import (
	"crypto/rand"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/common"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/utils"
)

var (
	testSlot     = uint(4)
	testNumSlots = 10
	userpin      = "12345670"
)

func init() {
	SetSlot(testSlot)
	logrus.SetLevel(logrus.DebugLevel)
}

func getKeyStoreAndSession(t *testing.T) (*KeyStore, pkcs11.SessionHandle) {
	ks := NewKeyStore()
	session, err := ks.SetupHSMEnv()
	require.NoError(t, err)
	return ks, session
}

func clearAllKeys(t *testing.T) {
	ks, session := getKeyStoreAndSession(t)
	defer ks.CloseSession(session)
	list, err := ks.HardwareListKeys(session)
	require.NoError(t, err)
	t.Logf("Found %d keys", len(list))
	i := 0
	for id, slot := range list {
		err = ks.HardwareRemoveKey(session, slot, userpin, id)
		require.NoError(t, err)
		i++
	}
	t.Logf("Cleared %d keys", i)
}

func TestAddAndRetrieveKey(t *testing.T) {
	defer Cleanup()
	clearAllKeys(t)
	ks, session := getKeyStoreAndSession(t)
	defer ks.CloseSession(session)
	privKey, err := utils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)
	slotID, err := ks.GetNextEmptySlot(session)
	require.NoError(t, err)
	slot := common.HardwareSlot{
		Role:   data.CanonicalRootRole,
		SlotID: slotID,
		KeyID:  privKey.ID(),
	}
	err = ks.AddECDSAKey(session, privKey, slot, userpin, data.CanonicalRootRole)
	require.NoError(t, err)
	pubKey, role, err := ks.GetECDSAKey(session, slot, userpin)
	require.NoError(t, err)
	require.Equal(t, role, data.CanonicalRootRole)
	require.Equal(t, privKey.Public(), pubKey.Public())
}
