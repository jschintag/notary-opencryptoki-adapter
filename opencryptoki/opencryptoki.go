package opencryptoki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/common"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/externalstore"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/utils"
)

var (
	tokenSlot uint
	pkcs11Lib string
	pkcs11Ctx common.IPKCS11Ctx = nil
)

const (
	name        = "openCryptoki"
	numSlots    = 999
	ockReqMajor = 3
	ockReqMinor = 8
)

// KeyStore is the hardwarespecific keystore implementing all functions
type KeyStore struct {
}

// NewKeyStore looks up all possible filepaths for opencryptoki library and if it finds one, sets it up for further usage
func NewKeyStore() *KeyStore {
	if possiblePkcs11Libs != nil {
		for _, loc := range possiblePkcs11Libs {
			_, err := os.Stat(loc)
			if err == nil {
				p := pkcs11.New(loc)
				if p != nil {
					pkcs11Lib = loc
				}
			}
		}
	}
	return &KeyStore{}
}

//Name returns the hardwarestores name
func (ks *KeyStore) Name() string {
	return name
}

// Used to set the Token Slot
func SetSlot(slot uint) {
	tokenSlot = slot
}

// Finalizes and Destroys the Context
func Cleanup() {
	if pkcs11Ctx != nil {
		common.FinalizeAndDestroy(pkcs11Ctx)
		pkcs11Ctx = nil
	}
}

// AddECDSAKey adds a key to the opencryptoki store
func (ks *KeyStore) AddECDSAKey(session pkcs11.SessionHandle, privKey data.PrivateKey, hwslot common.HardwareSlot, passwd string, role data.RoleName) error {
	logrus.Debugf("Attempting to add key to %s with ID: %s", name, privKey.ID())
	err := pkcs11Ctx.Login(session, pkcs11.CKU_USER, passwd)
	if err != nil {
		return err
	}
	defer pkcs11Ctx.Logout(session)
	ecdsaPrivKey, err := x509.ParseECPrivateKey(privKey.Private())
	if err != nil {
		return err
	}

	ecdsaPrivKeyD := common.EnsurePrivateKeySize(ecdsaPrivKey.D.Bytes())

	startTime := time.Now()

	template, err := utils.NewCertificate(role.String(), startTime, startTime.AddDate(data.DefaultExpires(data.CanonicalRootRole).Year(), 0, 0))
	if err != nil {
		return fmt.Errorf("failed to create the certificate template: %v", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, ecdsaPrivKey.Public(), ecdsaPrivKey)
	ecdsaPrivKey = nil
	if err != nil {
		return fmt.Errorf("failed to create the certificate: %v", err)
	}
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "Notary Certificate"),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certBytes),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, template.SubjectKeyId),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hwslot.KeyID),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "Notary Private Key"),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hwslot.KeyID),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, ecdsaPrivKeyD),
	}

	_, err = pkcs11Ctx.CreateObject(session, certTemplate)
	if err != nil {
		return fmt.Errorf("error importing: %v", err)
	}

	_, err = pkcs11Ctx.CreateObject(session, privateKeyTemplate)
	if err != nil {
		return fmt.Errorf("error importing: %v", err)
	}

	return nil
}

//GetECDSAKey gets a key by id from the opencryptoki store
func (ks *KeyStore) GetECDSAKey(session pkcs11.SessionHandle, hwslot common.HardwareSlot, passwd string) (*data.ECDSAPublicKey, data.RoleName, error) {
	err := pkcs11Ctx.Login(session, pkcs11.CKU_USER, passwd)
	if err != nil {
		return nil, "", err
	}
	defer pkcs11Ctx.Logout(session)
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hwslot.KeyID),
	}
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{0}),
	}

	if err := pkcs11Ctx.FindObjectsInit(session, findTemplate); err != nil {
		logrus.Debugf("Failed to init: %s", err.Error())
		return nil, "", err
	}
	obj, _, err := pkcs11Ctx.FindObjects(session, 1)
	if err != nil {
		logrus.Debugf("Failed to find objects: %v", err)
		return nil, "", err
	}
	if err := pkcs11Ctx.FindObjectsFinal(session); err != nil {
		logrus.Debugf("Failed to finalize: %s", err.Error())
		return nil, "", err
	}
	if len(obj) != 1 {
		return nil, "", fmt.Errorf("no matching keys found inside of %s", name)
	}
	val, err := pkcs11Ctx.GetAttributeValue(session, obj[0], pubTemplate)
	if err != nil {
		logrus.Debugf("Failed to get Certificate for: %v", obj[0])
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(val[0].Value)
	pub := cert.PublicKey
	if err != nil {
		logrus.Debugf("Failed to parse Certificate for: %v", obj[0])
		return nil, "", err
	}
	attr := pub.(*ecdsa.PublicKey)
	ecdsaPubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: attr.X, Y: attr.Y}
	pubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPubKey)
	if err != nil {
		logrus.Debugf("Failed to Marshal public key")
		return nil, "", err
	}

	return data.NewECDSAPublicKey(pubBytes), data.CanonicalRootRole, nil
}

// Sign signs the payload with the key of the given ID
func (ks *KeyStore) Sign(session pkcs11.SessionHandle, hwslot common.HardwareSlot, passwd string, payload []byte) ([]byte, error) {
	err := pkcs11Ctx.Login(session, pkcs11.CKU_USER, passwd)
	if err != nil {
		return nil, fmt.Errorf("error logging in: %v", err)
	}
	defer pkcs11Ctx.Logout(session)

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hwslot.KeyID),
	}
	if err := pkcs11Ctx.FindObjectsInit(session, privateKeyTemplate); err != nil {
		logrus.Debugf("Failed to init find objects: %s", err.Error())
		return nil, err
	}
	obj, _, err := pkcs11Ctx.FindObjects(session, 1)

	if err != nil {
		logrus.Debugf("Failed to find objects: %v", err)
		return nil, err
	}
	if err = pkcs11Ctx.FindObjectsFinal(session); err != nil {
		logrus.Debugf("Failed to finalize find objects: %s", err.Error())
		return nil, err
	}
	if len(obj) != 1 {
		return nil, fmt.Errorf("should have found exactly one private key, found %d", len(obj))
	}

	var sig []byte
	err = pkcs11Ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, obj[0])
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(payload)
	sig, err = pkcs11Ctx.Sign(session, digest[:])
	if err != nil {
		logrus.Debugf("Error while signing: %s", err)
		return nil, err
	}

	if sig == nil {
		return nil, errors.New("Failed to create signature")
	}
	return sig[:], nil
}

// HardwareRemoveKey removes the Key with a specified ID from the opencryptoki store
func (ks *KeyStore) HardwareRemoveKey(session pkcs11.SessionHandle, hwslot common.HardwareSlot, passwd string, keyID string) error {
	err := pkcs11Ctx.Login(session, pkcs11.CKU_USER, passwd)
	if err != nil {
		return err
	}
	defer pkcs11Ctx.Logout(session)
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hwslot.KeyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_ID, hwslot.KeyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	templates := [][]*pkcs11.Attribute{certTemplate, keyTemplate}
	for _, template := range templates {
		if err := pkcs11Ctx.FindObjectsInit(session, template); err != nil {
			logrus.Debugf("Failed to init find objects: %s", err.Error())
			return err
		}
		obj, b, err := pkcs11Ctx.FindObjects(session, 1)
		if err != nil {
			logrus.Debugf("Failed to find objects: %s %v", err.Error(), b)
			return err
		}
		if err := pkcs11Ctx.FindObjectsFinal(session); err != nil {
			logrus.Debugf("Failed to finalize find objects: %s", err.Error())
			return err
		}
		if len(obj) != 1 {
			logrus.Debugf("should have found exactly one object")
			return err
		}

		err = pkcs11Ctx.DestroyObject(session, obj[0])
		if err != nil {
			logrus.Debugf("Failed to delete cert/privkey")
			return err
		}

	}

	return nil
}

//HardwareListKeys lists all available Keys stored by opencryptoki
func (ks *KeyStore) HardwareListKeys(session pkcs11.SessionHandle) (map[string]common.HardwareSlot, error) {
	keys := make(map[string]common.HardwareSlot)

	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0}),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{0}),
	}

	objs, err := ks.listObjects(session)
	if err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, common.ErrNoKeysFound{HSM: name}
	}
	logrus.Debugf("Found %d objects matching list filters", len(objs))
	for _, obj := range objs {
		var (
			cert *x509.Certificate
			slot []byte
		)
		attr, err := pkcs11Ctx.GetAttributeValue(session, obj, attrTemplate)
		if err != nil {
			logrus.Debugf("Failed to get Attribute for: %v", obj)
			continue
		}

		for _, a := range attr {
			if a.Type == pkcs11.CKA_ID {
				slot = a.Value
			}
			if a.Type == pkcs11.CKA_VALUE {
				cert, err = x509.ParseCertificate(a.Value)
				if err != nil {
					continue
				}
				if !data.ValidRole(data.RoleName(cert.Subject.CommonName)) {
					continue
				}
			}
		}

		if cert == nil {
			continue
		}

		var ecdsaPubKey *ecdsa.PublicKey
		switch cert.PublicKeyAlgorithm {
		case x509.ECDSA:
			ecdsaPubKey = cert.PublicKey.(*ecdsa.PublicKey)
		default:
			logrus.Infof("Unsupported x509 PublicKeyAlgorithm: %d", cert.PublicKeyAlgorithm)
			continue
		}

		pubBytes, err := x509.MarshalPKIXPublicKey(ecdsaPubKey)
		if err != nil {
			logrus.Debugf("Failed to Marshal public key")
			continue
		}
		id := data.NewECDSAPublicKey(pubBytes).ID()
		keys[id] = common.HardwareSlot{
			Role:   data.RoleName(cert.Subject.CommonName),
			SlotID: slot,
			KeyID:  id,
		}
	}
	return keys, err
}

func (ks *KeyStore) listObjects(session pkcs11.SessionHandle) ([]pkcs11.ObjectHandle, error) {
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	}

	if err := pkcs11Ctx.FindObjectsInit(session, findTemplate); err != nil {
		logrus.Debugf("Failed to init: %s", err.Error())
		return nil, err
	}
	objs, b, err := pkcs11Ctx.FindObjects(session, numSlots)
	for err == nil {
		var o []pkcs11.ObjectHandle
		o, b, err = pkcs11Ctx.FindObjects(session, numSlots)
		if err != nil {
			continue
		}
		if len(o) == 0 {
			break
		}
		objs = append(objs, o...)
	}
	if err != nil {
		logrus.Debugf("Failed to find: %s %v", err.Error(), b)
		if len(objs) == 0 {
			return nil, err
		}
	}
	if err := pkcs11Ctx.FindObjectsFinal(session); err != nil {
		logrus.Debugf("Failed to finalize: %s", err.Error())
		return nil, err
	}
	return objs, nil
}

//GetNextEmptySlot returns the first empty slot found by opencryptoki to store a key
func (ks *KeyStore) GetNextEmptySlot(session pkcs11.SessionHandle) ([]byte, error) {
	findTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{0}),
	}

	if err := pkcs11Ctx.FindObjectsInit(session, findTemplate); err != nil {
		logrus.Debugf("Failed to init: %s", err.Error())
		return nil, err
	}
	objs, b, err := pkcs11Ctx.FindObjects(session, numSlots)
	for err == nil {
		var o []pkcs11.ObjectHandle
		o, b, err = pkcs11Ctx.FindObjects(session, numSlots)
		if err != nil {
			continue
		}
		if len(o) == 0 {
			break
		}
		objs = append(objs, o...)
	}
	taken := make(map[int]bool)
	if err != nil {
		logrus.Debugf("Failed to find: %s %v", err.Error(), b)
		return nil, err
	}
	if err = pkcs11Ctx.FindObjectsFinal(session); err != nil {
		logrus.Debugf("Failed to finalize: %s\n", err.Error())
		return nil, err
	}
	for _, obj := range objs {
		attr, err := pkcs11Ctx.GetAttributeValue(session, obj, attrTemplate)
		if err != nil {
			continue
		}

		for _, a := range attr {
			if a.Type == pkcs11.CKA_ID {
				if len(a.Value) < 1 {
					continue
				}
				slotNum := int(a.Value[0])
				if slotNum >= numSlots {
					continue
				}
				taken[slotNum] = true
			}
		}
	}
	for loc := 0; loc < numSlots; loc++ {
		if !taken[loc] {
			return []byte{byte(loc)}, nil
		}
	}
	return nil, errors.New("Crypto Express has no available slots")
}

//SetupHSMEnv is responsible for opening the HSM session and performing some checks before (lib available, right version, mechanism available, etc)
func (ks *KeyStore) SetupHSMEnv() (pkcs11.SessionHandle, error) {
	p, err := initializeLib()
	if err != nil {
		return 0, err
	}
	err = hasECDSAMechanism(p, tokenSlot)
	if err != nil {
		defer common.FinalizeAndDestroy(p)
		return 0, fmt.Errorf("found library %s, but %s", pkcs11Lib, err)
	}
	session, err := p.OpenSession(tokenSlot, pkcs11.CKF_RW_SESSION|pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		defer common.Cleanup(p, session)
		return 0, fmt.Errorf(
			"loaded library %s, but failed to start session with HSM %s",
			pkcs11Lib, err)
	}
	return session, nil
}

// returns a printable string-representation of the available tokens
func (ks *KeyStore) PrintTokenSlots() {
	p, err := initializeLib()
	if err != nil {
		logrus.Errorf(err.Error())
		return
	}
	slots, err := p.GetSlotList(true)
	if err != nil {
		defer common.FinalizeAndDestroy(p)
		logrus.Errorf("loaded library %s, but failed to list HSM slots %s", pkcs11Lib, err)
		return
	}
	defer common.FinalizeAndDestroy(p)
	prettyPrintTokens(slots, os.Stdout, p)
}

// closes the pkcs11 Session
func (ks *KeyStore) CloseSession(session pkcs11.SessionHandle) {
	err := pkcs11Ctx.CloseSession(session)
	if err != nil {
		logrus.Debugf("Error closing session: %s", err.Error())
	}
}

// maps userFlag to function
func (ks *KeyStore) NeedLogin(function_id uint) (bool, uint, error) {
	switch function_id {
	case externalstore.FUNCTION_ADDECDSAKEY:
		return true, pkcs11.CKU_USER, nil
	case externalstore.FUNCTION_GETECDSAKEY:
		return true, pkcs11.CKU_USER, nil
	case externalstore.FUNCTION_SIGN:
		return true, pkcs11.CKU_USER, nil
	case externalstore.FUNCTION_HARDWAREREMOVEKEY:
		return true, pkcs11.CKU_USER, nil
	default:
		return true, pkcs11.CKU_CONTEXT_SPECIFIC, fmt.Errorf("Unknown Function")
	}
}

func initializeLib() (common.IPKCS11Ctx, error) {
	if pkcs11Ctx == nil {
		logrus.Debugf("initialize Lib")
		if pkcs11Lib == "" {
			return nil, common.ErrHSMNotPresent{Err: "no library found"}
		}
		p := pkcs11.New(pkcs11Lib)

		if p == nil {
			return nil, fmt.Errorf("failed to load library %s", pkcs11Lib)
		}

		if err := p.Initialize(); err != nil {
			defer common.FinalizeAndDestroy(p)
			return nil, fmt.Errorf("found library %s, but initialize error %s", pkcs11Lib, err.Error())
		}
		info, _ := p.GetInfo()
		if (info.LibraryVersion.Major >= ockReqMajor && info.LibraryVersion.Minor >= ockReqMinor) == false {
			defer common.FinalizeAndDestroy(p)
			return nil, fmt.Errorf("found library %s, but OpenCryptoki Version to low (3.8 Required)", pkcs11Lib)
		}
		pkcs11Ctx = p
	}
	return pkcs11Ctx, nil
}

func hasECDSAMechanism(p common.IPKCS11Ctx, slot uint) error {
	mechanisms, _ := p.GetMechanismList(slot)
	for _, mechanism := range mechanisms {
		if mechanism.Mechanism == pkcs11.CKM_ECDSA {
			return nil
		}
	}
	return errors.New("selected Token does not support ECDSA Mechanism")
}

func prettyPrintTokens(slots []uint, writer io.Writer, p common.IPKCS11Ctx) {
	fmt.Println("Available Tokens:")
	tw := initTabWriter([]string{"SLOT", "MODEL", "LABEL", "FLAGS"}, writer)

	for _, slot := range slots {
		info, _ := p.GetTokenInfo(uint(slot))
		fmt.Fprintf(
			tw,
			"%d\t%s\t%s\t%d\n",
			slot,
			info.Model,
			info.Label,
			info.Flags,
		)
	}
	tw.Flush()
}

func initTabWriter(columns []string, writer io.Writer) *tabwriter.Writer {
	tw := tabwriter.NewWriter(writer, 4, 4, 4, ' ', 0)
	fmt.Fprintln(tw, strings.Join(columns, "\t"))
	breakLine := make([]string, 0, len(columns))
	for _, h := range columns {
		breakLine = append(
			breakLine,
			strings.Repeat("-", len(h)),
		)
	}
	fmt.Fprintln(tw, strings.Join(breakLine, "\t"))
	return tw
}
