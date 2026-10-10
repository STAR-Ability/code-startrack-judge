// SPDX-License-Identifier: Apache-2.0

package imports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"sync"

	judgeruntime "github.com/STAR-Ability/code-startrack-judge/internal/runtime"
	"github.com/STAR-Ability/code-startrack-judge/internal/storage"
)

const evidenceChunkBytes = 1 << 20

type evidenceChunk struct {
	ObjectKey string `json:"objectKey"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

// evidenceJournal keeps ordered private NDJSON in bounded immutable chunks.
// Every chunk is durably staged before successful qualification can commit.
// The checksum covers the exact concatenation, independent of chunk boundaries.
type evidenceJournal struct {
	mu       sync.Mutex
	pipeline *ImportPipeline
	digest   hash.Hash
	count    uint64
	buffer   []byte
	stages   []storage.StagedObject
	failure  error
	sealed   bool
}

func newEvidenceJournal(p *ImportPipeline) *evidenceJournal {
	return &evidenceJournal{pipeline: p, digest: sha256.New()}
}

func (j *evidenceJournal) flush(ctx context.Context) error {
	if len(j.buffer) == 0 {
		return nil
	}
	stage, err := j.pipeline.stage(ctx, j.buffer)
	if err != nil {
		j.failure = ErrUnavailable
		return j.failure
	}
	j.stages = append(j.stages, stage)
	j.buffer = nil
	return nil
}

func (j *evidenceJournal) Record(ctx context.Context, event judgeruntime.ValidationEvidence) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failure != nil {
		return j.failure
	}
	if j.sealed || ctx.Err() != nil || j.count >= uint64(4096)*(128+4096) {
		j.failure = ErrUnavailable
		return j.failure
	}
	line, err := json.Marshal(event)
	if err != nil || len(line) > 16384 {
		j.failure = ErrUnavailable
		return j.failure
	}
	line = append(line, '\n')
	if len(j.buffer)+len(line) > evidenceChunkBytes {
		if err := j.flush(ctx); err != nil {
			return err
		}
	}
	j.buffer = append(j.buffer, line...)
	j.digest.Write(line)
	j.count++
	return nil
}

func (j *evidenceJournal) Seal(ctx context.Context, checksum string, count uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failure != nil {
		return j.failure
	}
	expected := hex.EncodeToString(j.digest.Sum(nil))
	if j.sealed || count != j.count || checksum != expected && !(count == 0 && checksum == "") {
		j.failure = ErrUnavailable
		return j.failure
	}
	if err := j.flush(ctx); err != nil {
		return err
	}
	j.sealed = true
	return nil
}

// SealIncomplete retains the accepted event prefix, including its final partial
// chunk. Its own hash/count describe only that prefix, never helper completeness.
func (j *evidenceJournal) SealIncomplete(ctx context.Context) (string, uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.sealed {
		return "", 0, ErrUnavailable
	}
	if err := j.flush(ctx); err != nil {
		return "", 0, err
	}
	j.sealed = true
	return hex.EncodeToString(j.digest.Sum(nil)), j.count, nil
}

func (j *evidenceJournal) Stages() []storage.StagedObject {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]storage.StagedObject(nil), j.stages...)
}
func (j *evidenceJournal) Chunks() []evidenceChunk {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make([]evidenceChunk, 0, len(j.stages))
	for _, stage := range j.stages {
		result = append(result, evidenceChunk{stage.Object.Key, stage.Object.SHA256, stage.Object.SizeBytes})
	}
	return result
}
func (j *evidenceJournal) Count() uint64 { j.mu.Lock(); defer j.mu.Unlock(); return j.count }
