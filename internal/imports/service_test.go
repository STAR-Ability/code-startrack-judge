package imports

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/STAR-Ability/code-startrack-judge/internal/canonical"
	"github.com/STAR-Ability/code-startrack-judge/internal/contract"
)

type admissionRepo struct {
	job      contract.ImportJob
	hash     string
	err      error
	accepted int
}

func (r *admissionRepo) FindByRequest(context.Context, contract.UUID) (contract.ImportJob, string, error) {
	return r.job, r.hash, r.err
}
func (r *admissionRepo) Accept(_ context.Context, _ contract.ImportRequest, _ string) (contract.ImportJob, bool, error) {
	r.accepted++
	return r.job, true, nil
}
func (r *admissionRepo) Get(context.Context, contract.UUID) (contract.ImportJob, error) {
	return r.job, r.err
}

func validRequest() contract.ImportRequest {
	return contract.ImportRequest{RequestID: "01a11732-f75e-4071-b05e-95470a67323a", Source: "OJ_LAB", RepositoryURL: contract.PackageRepository, Revision: "cd416d900bab657acdcd96d77b629efa02cae8d4", PackagePaths: contract.Array[string]{"problems/example"}}
}
func TestAcceptedReplayPrecedesReadinessAndFreezesIdentity(t *testing.T) {
	request := validRequest()
	raw, _ := json.Marshal(request)
	hash, _ := canonical.RequestHash("IMPORT", nil, raw)
	r := &admissionRepo{hash: hash, job: contract.ImportJob{ImportJobID: "01a11732-f75e-4071-b05e-95470a67323b", Status: contract.ImportFailed}}
	readyCalls := 0
	s := New(r, func(context.Context) bool { readyCalls++; return false })
	job, created, err := s.Submit(context.Background(), request)
	if err != nil || created || job.Status != contract.ImportFailed || readyCalls != 0 || r.accepted != 0 {
		t.Fatal("accepted failed job replay depended on current admission state")
	}
	request.PackagePaths = contract.Array[string]{"problems/changed"}
	if _, _, err = s.Submit(context.Background(), request); err != ErrConflict || readyCalls != 0 {
		t.Fatal("conflicting identity was reinterpreted")
	}
	r.err = ErrNotFound
	if _, _, err = s.Submit(context.Background(), request); err != ErrUnavailable || r.accepted != 0 {
		t.Fatal("unavailable fresh request reserved an identity")
	}
	request.PackagePaths = contract.Array[string]{"problems/../escape"}
	if _, _, err = s.Submit(context.Background(), request); err == nil || r.accepted != 0 {
		t.Fatal("invalid source selection reached admission")
	}
}

type workerRepo struct{ completed int }

func (*workerRepo) Claim(context.Context) (*Lease, error)  { return nil, nil }
func (*workerRepo) Heartbeat(context.Context, Lease) error { return nil }
func (r *workerRepo) CompleteItem(context.Context, Lease, PendingItem, Prepared) error {
	r.completed++
	return nil
}

type ambiguousPipeline struct{ dispatched int }

func (p *ambiguousPipeline) Prepare(context.Context, Lease, PendingItem) (Prepared, error) {
	p.dispatched++
	return nil, ErrUnavailable
}
func TestAmbiguousPipelineStopsReservationWithoutReplay(t *testing.T) {
	r := &workerRepo{}
	p := &ambiguousPipeline{}
	w := Worker{Repository: r, Pipeline: p, Ready: func(context.Context) bool { return true }}
	w.execute(context.Background(), Lease{Items: []PendingItem{{PackagePath: "problems/one"}, {PackagePath: "problems/two"}}})
	if p.dispatched != 1 || r.completed != 0 {
		t.Fatal("ambiguous execution was replayed or committed under the same reservation")
	}
}
