package manifest

import (
	"context"
	"fmt"
)

// GeneratorPort generates an integrity manifest from observation files.
type GeneratorPort interface {
	GenerateManifest(ctx context.Context, req GenerateRequest) (GenerateResponse, error)
}

// GenerateDeps groups the port interfaces for the generate use case.
type GenerateDeps struct {
	Generator GeneratorPort
}

// Generate generates an unsigned integrity manifest for observation snapshots.
func Generate(ctx context.Context, req GenerateRequest, deps GenerateDeps) (GenerateResponse, error) {
	if err := ctx.Err(); err != nil {
		return GenerateResponse{}, fmt.Errorf("manifest-generate: %w", err)
	}
	if req.ObservationsDir == "" {
		return GenerateResponse{}, fmt.Errorf("manifest-generate: observations directory is required")
	}

	resp, err := deps.Generator.GenerateManifest(ctx, req)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("manifest-generate: %w", err)
	}
	return resp, nil
}

// SignerPort signs an integrity manifest with a private key.
type SignerPort interface {
	SignManifest(ctx context.Context, req SignRequest) (SignResponse, error)
}

// SignDeps groups the port interfaces for the sign use case.
type SignDeps struct {
	Signer SignerPort
}

// Sign signs an unsigned integrity manifest with an Ed25519 private key.
func Sign(ctx context.Context, req SignRequest, deps SignDeps) (SignResponse, error) {
	if err := ctx.Err(); err != nil {
		return SignResponse{}, fmt.Errorf("manifest-sign: %w", err)
	}
	if req.InPath == "" {
		return SignResponse{}, fmt.Errorf("manifest-sign: input manifest path is required")
	}
	if req.PrivateKeyPath == "" {
		return SignResponse{}, fmt.Errorf("manifest-sign: private key path is required")
	}

	resp, err := deps.Signer.SignManifest(ctx, req)
	if err != nil {
		return SignResponse{}, fmt.Errorf("manifest-sign: %w", err)
	}
	return resp, nil
}

// KeypairGeneratorPort generates an Ed25519 signing keypair.
type KeypairGeneratorPort interface {
	GenerateKeypair(ctx context.Context, req KeygenRequest) (KeygenResponse, error)
}

// KeygenDeps groups the port interfaces for the keygen use case.
type KeygenDeps struct {
	Generator KeypairGeneratorPort
}

// Keygen generates an Ed25519 keypair for manifest signing.
func Keygen(ctx context.Context, req KeygenRequest, deps KeygenDeps) (KeygenResponse, error) {
	if err := ctx.Err(); err != nil {
		return KeygenResponse{}, fmt.Errorf("manifest-keygen: %w", err)
	}
	if req.PrivateKeyPath == "" {
		return KeygenResponse{}, fmt.Errorf("manifest-keygen: private key output path is required")
	}
	if req.PublicKeyPath == "" {
		return KeygenResponse{}, fmt.Errorf("manifest-keygen: public key output path is required")
	}

	resp, err := deps.Generator.GenerateKeypair(ctx, req)
	if err != nil {
		return KeygenResponse{}, fmt.Errorf("manifest-keygen: %w", err)
	}
	return resp, nil
}
