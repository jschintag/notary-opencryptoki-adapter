package main

import (
	"github.com/miekg/pkcs11"
	"github.com/jschintag/notary-opencryptoki-adapter/opencryptoki"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/externalstore"
)

type ESServer struct {
}

var (
	ks *opencryptoki.KeyStore = opencryptoki.NewKeyStore()
)

func NewServer(tokenSlot uint) externalstore.ESServer {
	opencryptoki.SetSlot(tokenSlot)
	return new(ESServer)
}

// Prints the available Tokens
func PrintTokenSlots() {
	ks.PrintTokenSlots()
}

func (s *ESServer) Name(req externalstore.ESNameReq, res *externalstore.ESNameRes) error {
	res.Name = ks.Name()
	return nil
}

func (s *ESServer) AddECDSAKey(req externalstore.ESAddECDSAKeyReq, res *externalstore.ESAddECDSAKeyRes) error {
	session := pkcs11.SessionHandle(req.Session)
	privKey, err := externalstore.ESPrivateKeyToPrivateKey(req.PrivateKey)
	if err != nil {
		return err
	}
	return ks.AddECDSAKey(session, privKey, req.Slot, req.Pass, req.Role)
}

func (s *ESServer) GetECDSAKey(req externalstore.ESGetECDSAKeyReq, res *externalstore.ESGetECDSAKeyRes) error {
	session := pkcs11.SessionHandle(req.Session)
	pubKey, role, err := ks.GetECDSAKey(session, req.Slot, req.Pass)
	if err != nil {
		return err
	}
	res.PublicKey = externalstore.NewESPublicKey(pubKey)
	res.Role = role
	return nil
}

func (s *ESServer) Sign(req externalstore.ESSignReq, res *externalstore.ESSignRes) error {
	session := pkcs11.SessionHandle(req.Session)
	result, err := ks.Sign(session, req.Slot, req.Pass, req.Payload)
	if err != nil {
		return err
	}
	res.Result = result
	return nil
}

func (s *ESServer) HardwareRemoveKey(req externalstore.ESHardwareRemoveKeyReq, res *externalstore.ESHardwareRemoveKeyRes) error {
	session := pkcs11.SessionHandle(req.Session)
	return ks.HardwareRemoveKey(session, req.Slot, req.Pass, req.KeyID)
}

func (s *ESServer) HardwareListKeys(req externalstore.ESHardwareListKeysReq, res *externalstore.ESHardwareListKeysRes) error {
	session := pkcs11.SessionHandle(req.Session)
	keys, err := ks.HardwareListKeys(session)
	if err != nil {
		return err
	}
	res.Keys = keys
	return nil
}

func (s *ESServer) GetNextEmptySlot(req externalstore.ESGetNextEmptySlotReq, res *externalstore.ESGetNextEmptySlotRes) error {
	session := pkcs11.SessionHandle(req.Session)
	slot, err := ks.GetNextEmptySlot(session)
	if err != nil {
		return err
	}
	res.Slot = slot
	return nil
}

func (s *ESServer) SetupHSMEnv(req externalstore.ESSetupHSMEnvReq, res *externalstore.ESSetupHSMEnvRes) error {
	session, err := ks.SetupHSMEnv()
	if err != nil {
		return err
	}
	res.Session = uint(session)
	return nil
}

func (s *ESServer) Cleanup(req externalstore.ESCleanupReq, _ *externalstore.ESCleanupReq) error {
	session := pkcs11.SessionHandle(req.Session)
	ks.CloseSession(session)
	return nil
}

func (s *ESServer) NeedLogin(req externalstore.ESNeedLoginReq, res *externalstore.ESNeedLoginRes) error {
	needed, userFlag, err := ks.NeedLogin(req.Function_ID)
	if err != nil {
		return err
	}
	res.NeedLogin = needed
	res.UserFlag = userFlag
	return nil
}
