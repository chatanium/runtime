//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"strings"
)

func (s *ownedSession) selectWorkerRevision(ctx context.Context, mode RunMode, options RunOptions) (host.RevisionRecord, error) {
	revision, e := s.store.Revision(ctx, s.manifest.ActiveRevision)
	if e != nil {
		return revision, e
	}
	if options.DevelopmentRevision == "" {
		return revision, nil
	}
	if mode != Foreground || !options.DevelopmentMode {
		return host.RevisionRecord{}, errors.New("development worker selection requires explicit foreground development mode")
	}
	if e = verifyInstalledLauncher(ctx, s); e != nil {
		return host.RevisionRecord{}, e
	}
	development, e := s.store.Revision(ctx, options.DevelopmentRevision)
	if e != nil {
		return host.RevisionRecord{}, e
	}
	binding := development.DevelopmentWorker
	if binding == nil || binding.BaseRevision != revision.ID || development.BundleDigest != revision.BundleDigest || development.ConfigDigest != revision.ConfigDigest {
		return host.RevisionRecord{}, errors.New("development worker is not bound to the active release")
	}
	if _, e = s.images.DevelopmentWorker(ctx, binding.JobID, binding.ArtifactDigest); e != nil {
		return host.RevisionRecord{}, e
	}
	refs, e := s.store.GenerationReferences(ctx)
	if e != nil {
		return host.RevisionRecord{}, e
	}
	retained := false
	generation := "development-worker:" + binding.JobID
	for _, ref := range refs {
		if ref.Kind == "preparation" && ref.ID == generation && ref.Claim == "dev-revision:"+development.ID {
			retained = true
		}
	}
	if !retained {
		return host.RevisionRecord{}, errors.New("development worker generation is retired or unretained")
	}
	claim := "worker-epoch:" + s.supervisor.EpochID()
	if e = s.store.RetainGeneration(ctx, "live", generation, claim); e != nil {
		return host.RevisionRecord{}, e
	}
	s.workerReferences = append(s.workerReferences, host.GenerationReference{Kind: "live", ID: generation, Claim: claim})
	return development, nil
}
func staleWorkerReferences(ctx context.Context, store *host.Store) ([]host.GenerationReference, error) {
	refs, e := store.GenerationReferences(ctx)
	if e != nil {
		return nil, e
	}
	var workers []host.GenerationReference
	for _, ref := range refs {
		if ref.Kind == "live" && strings.HasPrefix(ref.ID, "development-worker:") {
			if !strings.HasPrefix(ref.Claim, "worker-epoch:") {
				return nil, errors.New("unrecognized retained worker ownership")
			}
			workers = append(workers, ref)
		}
	}
	return workers, nil
}
