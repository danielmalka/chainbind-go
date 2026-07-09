// Package agenticcheckout implements the agentic-checkout/v1 profile on top
// of chainbind's domain-free core (D-004). Every checkout-specific name —
// user, merchant, gateway, checkout, payment, transaction, subject — lives in
// this package alone; the core knows only opaque audience names and
// data-driven bindings.
package agenticcheckout

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/danielmalka/chainbind-go/pkg/chainbind"
)

// Name is the value stamped into SealRequest.Profile and Package.Profile for
// packages sealed under this profile.
const Name = "agentic-checkout/v1"

// Audience names this profile splits a Payload into. The core places no
// meaning on these beyond using them as map/manifest keys (D-004); they are
// this profile's own vocabulary.
const (
	AudienceUser     = "user"
	AudienceMerchant = "merchant"
	AudienceGateway  = "gateway"
)

// Sentinel errors. Static strings only (architecture invariant 10): never a
// payload value, a hash, a key, or a length.
var (
	// ErrUnsupportedPayload is returned by Split and Project when payload
	// is neither a Payload nor a *Payload.
	ErrUnsupportedPayload = errors.New("agenticcheckout: unsupported payload type")

	// ErrMissingSegmentHash is returned by a BindingSpec when a plain_hash
	// its formula needs is absent from BindingContext.PlainHash. The
	// audience the hash belongs to is deliberately not named in the
	// string.
	ErrMissingSegmentHash = errors.New("agenticcheckout: missing segment plain_hash")
)

// RequestContext is envelope metadata: request routing and tracing
// information, not business data. It is never split into a segment; its
// fields feed SealRequest.TenantID/Environment.
type RequestContext struct {
	TenantID      string `json:"tenant_id"`
	Environment   string `json:"environment"`
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`
	IssuedBy      string `json:"issued_by"`
}

// Intent is envelope metadata naming which authorization this execution is
// checked against and where. Like RequestContext, it is never split into a
// segment; its fields feed SealRequest.IntentRef/Authority.
type Intent struct {
	IntentRef string `json:"intent_ref"`
	Authority string `json:"authority"`
}

// Subject is the user-facing business section. It becomes the "user"
// audience's segment verbatim.
type Subject struct {
	UserID        string   `json:"user_id"`
	AccountID     string   `json:"account_id"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	AccountStatus string   `json:"account_status"`
}

// Item is one line item in a Checkout.
type Item struct {
	SKU       string `json:"sku"`
	Name      string `json:"name"`
	Quantity  int64  `json:"quantity"`
	UnitPrice int64  `json:"unit_price"`
}

// Checkout is the merchant-facing business section. It becomes the
// "merchant" audience's segment verbatim.
type Checkout struct {
	CheckoutID   string `json:"checkout_id"`
	MerchantID   string `json:"merchant_id"`
	MerchantName string `json:"merchant_name"`
	Currency     string `json:"currency"`
	Items        []Item `json:"items"`
	Subtotal     int64  `json:"subtotal"`
	Shipping     int64  `json:"shipping"`
	Discount     int64  `json:"discount"`
	Total        int64  `json:"total"`
}

// Payment is the gateway-facing business section. It becomes the "gateway"
// audience's segment verbatim.
type Payment struct {
	PaymentID         string `json:"payment_id"`
	PaymentMethod     string `json:"payment_method"`
	BankAccountMasked string `json:"bank_account_masked"`
	BankCode          string `json:"bank_code"`
	PaymentReference  string `json:"payment_reference"`
	TransactionStatus string `json:"transaction_status"`
	Amount            int64  `json:"amount"`
}

// Payload is the agentic-checkout/v1 shape (docs/payload-example.json). Per
// PRD §6 assumption A3, its three business sections — Subject, Checkout,
// Payment — map one-to-one onto the three audiences: no field belongs to
// two. RequestContext and Intent are envelope metadata, not segment
// material: they feed the SealRequest fields the core itself already
// understands (TenantID, Environment, IntentRef, Authority), never a
// segment.
type Payload struct {
	RequestContext RequestContext `json:"request_context"`
	Intent         Intent         `json:"intent"`
	Subject        Subject        `json:"subject"`
	Checkout       Checkout       `json:"checkout"`
	Payment        Payment        `json:"payment"`
}

// Projection is what Seal sends to the intent authority (D-009): only the
// fields policy needs, never the payload. No timestamp is projected,
// deliberately — this profile's Payload carries none. A deployment that
// binds time-based constraints (recurrence, budget windows) must add an
// issued_at field to Payload and project it here; its absence today is not
// an oversight.
type Projection struct {
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
	MerchantID string `json:"merchant_id"`
}

// Profile implements chainbind.Profile for the agentic-checkout/v1 shape.
type Profile struct{}

var _ chainbind.Profile = Profile{}

// SegmentOrder returns {user, merchant, gateway}, a fresh slice each call so
// a caller cannot mutate a shared package-level slice.
func SegmentOrder() []string {
	return []string{AudienceUser, AudienceMerchant, AudienceGateway}
}

// asPayload accepts a Payload or *Payload and returns it by value;
// everything else is ErrUnsupportedPayload.
func asPayload(payload any) (Payload, error) {
	switch v := payload.(type) {
	case Payload:
		return v, nil
	case *Payload:
		if v == nil {
			return Payload{}, ErrUnsupportedPayload
		}
		return *v, nil
	default:
		return Payload{}, ErrUnsupportedPayload
	}
}

// Split implements chainbind.Profile. It maps Payload's three business
// sections one-to-one onto the three audiences (A3): user <- Subject,
// merchant <- Checkout, gateway <- Payment. request_context and intent are
// envelope metadata, not segment material, and never appear here.
//
// Each segment is plain json.Marshal of its section, not JCS: the core
// canonicalizes with JCS itself when it hashes a segment's plaintext
// (seal.go), so canonicalizing here too would be redundant, not more
// correct. Do not "fix" this.
func (Profile) Split(payload any) (map[string][]byte, error) {
	p, err := asPayload(payload)
	if err != nil {
		return nil, err
	}

	user, err := json.Marshal(p.Subject)
	if err != nil {
		return nil, fmt.Errorf("agenticcheckout: split: %w", err)
	}
	merchant, err := json.Marshal(p.Checkout)
	if err != nil {
		return nil, fmt.Errorf("agenticcheckout: split: %w", err)
	}
	gateway, err := json.Marshal(p.Payment)
	if err != nil {
		return nil, fmt.Errorf("agenticcheckout: split: %w", err)
	}

	return map[string][]byte{
		AudienceUser:     user,
		AudienceMerchant: merchant,
		AudienceGateway:  gateway,
	}, nil
}

// Project implements chainbind.Profile. It returns exactly the three fields
// the intent authority's policy needs (D-009) — never the payload, never
// more than these three.
func (Profile) Project(payload any) (any, error) {
	p, err := asPayload(payload)
	if err != nil {
		return nil, err
	}
	return Projection{
		Amount:     p.Payment.Amount,
		Currency:   p.Checkout.Currency,
		MerchantID: p.Checkout.MerchantID,
	}, nil
}

// transactionIDInput is the object transaction_id hashes over.
type transactionIDInput struct {
	CheckoutHash     string `json:"checkout_hash"`
	GatewayPlainHash string `json:"gateway_plain_hash"`
}

// BindingSpecs returns this profile's three bindings, each a pure function
// of chainbind.BindingContext: checkout_hash, transaction_id and
// conditional_transaction_id. None reads a previously computed binding —
// every formula is expressed purely in terms of BindingContext's own
// fields.
func BindingSpecs() []chainbind.BindingSpec {
	return []chainbind.BindingSpec{
		{Name: "checkout_hash", Compute: computeCheckoutHash},
		{Name: "transaction_id", Compute: computeTransactionID},
		{Name: "conditional_transaction_id", Compute: computeConditionalTransactionID},
	}
}

// computeCheckoutHash aliases the merchant segment's plain_hash. It is not a
// new hash — merely a checkout-vocabulary name for a value the core already
// computed.
func computeCheckoutHash(bctx chainbind.BindingContext) (string, error) {
	h, ok := bctx.PlainHash[AudienceMerchant]
	if !ok {
		return "", ErrMissingSegmentHash
	}
	return h, nil
}

// computeTransactionID computes transaction_id = "txn:" +
// H(JCS({checkout_hash, gateway_plain_hash})) (TECHSPEC-001 §6.1).
//
// TECHSPEC-001 §6.2 / D-007: transaction_id is not a security control. Both
// of its inputs — checkout_hash (an alias of the merchant segment's
// plain_hash) and the gateway segment's plain_hash — already sit inside the
// signed manifest, so any verifier recomputes it holding no key and opening
// nothing; it adds no evidence the signature did not already provide. It
// exists to be a stable, collision-resistant name for "this cart paid by
// this payment" — for correlation and idempotency across systems that need
// one. Treating it as protection is security theater.
func computeTransactionID(bctx chainbind.BindingContext) (string, error) {
	checkoutHash, ok := bctx.PlainHash[AudienceMerchant]
	if !ok {
		return "", ErrMissingSegmentHash
	}
	gatewayPlainHash, ok := bctx.PlainHash[AudienceGateway]
	if !ok {
		return "", ErrMissingSegmentHash
	}

	canon, err := chainbind.JCS(transactionIDInput{
		CheckoutHash:     checkoutHash,
		GatewayPlainHash: gatewayPlainHash,
	})
	if err != nil {
		return "", fmt.Errorf("agenticcheckout: transaction_id: %w", err)
	}
	return "txn:" + chainbind.H(canon), nil
}

// computeConditionalTransactionID aliases intent_commitment (D-008): it
// recomputes chainbind.IntentCommitment from BindingContext's own
// IntentRef/ConstraintsHash/SegmentsRoot rather than reading
// bindings.intent_commitment, which BindingContext does not carry.
// Recomputing from the same three inputs is exact.
func computeConditionalTransactionID(bctx chainbind.BindingContext) (string, error) {
	commitment, err := chainbind.IntentCommitment(bctx.IntentRef, bctx.ConstraintsHash, bctx.SegmentsRoot)
	if err != nil {
		return "", fmt.Errorf("agenticcheckout: conditional_transaction_id: %w", err)
	}
	return commitment, nil
}
