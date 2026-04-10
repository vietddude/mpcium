package sdkflow

import "github.com/fystack/mpcium/pkg/event"

type Protocol string

const (
	ProtocolECDSA Protocol = "ecdsa"
	ProtocolEdDSA Protocol = "eddsa"
)

type Operation string

const (
	OperationKeygen Operation = "keygen"
	OperationSign   Operation = "sign"
)

type ParticipantType string

const (
	ParticipantNode   ParticipantType = "node"
	ParticipantMobile ParticipantType = "cosigner_mobile"
	ParticipantServer ParticipantType = "cosigner_server"
)

type Participant struct {
	ID                   string          `json:"id"`
	ParticipantType      ParticipantType `json:"participant_type"`
	Moniker              string          `json:"moniker,omitempty"`
	UniqueKeyHex         string          `json:"unique_key_hex,omitempty"`
	IdentityPublicKeyHex string          `json:"identity_public_key_hex"`
}

type SessionContext struct {
	SessionID          string        `json:"session_id"`
	WalletID           string        `json:"wallet_id"`
	Protocol           Protocol      `json:"protocol"`
	Operation          Operation     `json:"operation"`
	LocalParticipantID string        `json:"local_participant_id"`
	Threshold          uint16        `json:"threshold"`
	Participants       []Participant `json:"participants"`
}

type KeygenRequest struct {
	Session SessionContext `json:"session"`
}

type SignRequest struct {
	Session          SessionContext `json:"session"`
	SignerIndexes    []uint16       `json:"signer_indexes"`
	MessageDigestHex string         `json:"message_digest_hex"`
	ChainCodeHex     string         `json:"chain_code_hex,omitempty"`
	DerivationPath   []uint32       `json:"derivation_path,omitempty"`
}

type KeygenResult struct {
	SessionID string `json:"session_id"`
	WalletID  string `json:"wallet_id"`
	Protocol  string `json:"protocol"`
	ShareRef  string `json:"share_ref"`
	PubKey    []byte `json:"pub_key,omitempty"`

	ResultType  event.ResultType `json:"result_type"`
	ErrorReason string           `json:"error_reason,omitempty"`
	ErrorCode   event.ErrorCode  `json:"error_code,omitempty"`
}

type SignResult struct {
	SessionID string `json:"session_id"`
	WalletID  string `json:"wallet_id"`
	Protocol  string `json:"protocol"`

	Signature         []byte `json:"signature,omitempty"`
	SignatureRecovery []byte `json:"signature_recovery,omitempty"`
	R                 []byte `json:"r,omitempty"`
	S                 []byte `json:"s,omitempty"`

	ResultType  event.ResultType `json:"result_type"`
	ErrorReason string           `json:"error_reason,omitempty"`
	ErrorCode   event.ErrorCode  `json:"error_code,omitempty"`
}
