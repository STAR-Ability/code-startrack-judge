package restclient

import (
	"encoding/json"
	"math"
)

// These project-owned wire projections follow go-judge v1.13.0 model/model.go.
// They intentionally omit unsupported host-path, inline-content, pipe-mapping,
// interactive and deprecated fields. No sandbox implementation is copied.
type wireFile struct {
	FileID *FileID `json:"fileId,omitempty"`
	Name   *string `json:"name,omitempty"`
	Max    *int64  `json:"max,omitempty"`
	Pipe   bool    `json:"pipe,omitempty"`
}

type wireCommand struct {
	Args              []string            `json:"args"`
	Env               []string            `json:"env,omitempty"`
	Files             []wireFile          `json:"files"`
	CPULimit          uint64              `json:"cpuLimit"`
	ClockLimit        uint64              `json:"clockLimit"`
	MemoryLimit       uint64              `json:"memoryLimit"`
	StackLimit        uint64              `json:"stackLimit"`
	ProcLimit         uint64              `json:"procLimit"`
	CopyIn            map[string]wireFile `json:"copyIn"`
	CopyOutCached     []string            `json:"copyOutCached"`
	CopyOutMax        uint64              `json:"copyOutMax"`
	StrictMemoryLimit bool                `json:"strictMemoryLimit"`
	DataSegmentLimit  bool                `json:"dataSegmentLimit"`
	AddressSpaceLimit bool                `json:"addressSpaceLimit"`
}

type wireRequest struct {
	RequestID string        `json:"requestId"`
	Commands  []wireCommand `json:"cmd"`
}

func encodeRequest(r Request) ([]byte, error) {
	w := wireRequest{RequestID: r.RequestID, Commands: make([]wireCommand, len(r.Commands))}
	for i, c := range r.Commands {
		wc := wireCommand{Args: c.Args, Env: c.Env, Files: make([]wireFile, len(c.Files)), CPULimit: c.CPULimitNS, ClockLimit: c.ClockLimitNS, MemoryLimit: c.MemoryLimitBytes, StackLimit: c.StackLimitBytes, ProcLimit: c.ProcessLimit, CopyIn: make(map[string]wireFile, len(c.CopyIn)), CopyOutCached: make([]string, 0, len(c.CopyOutCached)), CopyOutMax: c.CopyOutMaxBytes, StrictMemoryLimit: c.StrictMemoryLimit, DataSegmentLimit: c.DataSegmentLimit, AddressSpaceLimit: c.AddressSpaceLimit}
		for j, file := range c.Files {
			if file.ID != "" {
				id := file.ID
				wc.Files[j].FileID = &id
			} else {
				name, max := file.Collector, file.LimitBytes
				wc.Files[j] = wireFile{Name: &name, Max: &max, Pipe: file.CollectPipe}
			}
		}
		for name, fileID := range c.CopyIn {
			id := fileID
			wc.CopyIn[name] = wireFile{FileID: &id}
		}
		for _, output := range c.CopyOutCached {
			name := output.Name
			if output.Optional {
				name += "?"
			}
			wc.CopyOutCached = append(wc.CopyOutCached, name)
		}
		w.Commands[i] = wc
	}
	return json.Marshal(w)
}

type wireFileError struct {
	Name    string        `json:"name"`
	Type    FileErrorType `json:"type"`
	Message string        `json:"message,omitempty"`
}

type wireResult struct {
	Status     *Status           `json:"status"`
	ExitStatus *int              `json:"exitStatus"`
	Error      string            `json:"error,omitempty"`
	Time       *uint64           `json:"time"`
	Memory     *uint64           `json:"memory"`
	RunTime    *uint64           `json:"runTime"`
	ProcPeak   uint64            `json:"procPeak,omitempty"`
	Files      map[string]string `json:"files,omitempty"`
	FileIDs    map[string]FileID `json:"fileIds,omitempty"`
	FileError  []wireFileError   `json:"fileError,omitempty"`
}

func projectResults(w []wireResult, req Request, limits Limits) ([]Result, error) {
	if len(w) != len(req.Commands) {
		return nil, &Error{Kind: ProtocolError}
	}
	results := make([]Result, len(w))
	totalFiles := 0
	inputIDs := make(map[FileID]bool)
	for _, command := range req.Commands {
		for _, file := range command.Files {
			if file.ID != "" {
				inputIDs[file.ID] = true
			}
		}
		for _, id := range command.CopyIn {
			inputIDs[id] = true
		}
	}
	outputIDs := make(map[FileID]bool)
	for i, value := range w {
		if value.Status == nil || !value.Status.valid() || value.ExitStatus == nil || *value.ExitStatus < 0 || *value.ExitStatus > math.MaxInt32 || value.Time == nil || *value.Time > math.MaxInt64 || value.Memory == nil || *value.Memory > math.MaxInt64 || value.RunTime == nil || *value.RunTime > math.MaxInt64 || len(value.Files) != 0 || len(value.FileError) > limits.Files {
			return nil, &Error{Kind: ProtocolError}
		}
		requested := make(map[string]Output, len(req.Commands[i].CopyOutCached))
		for _, output := range req.Commands[i].CopyOutCached {
			requested[output.Name] = output
		}
		collectors := make(map[string]bool)
		for _, file := range req.Commands[i].Files {
			if file.Collector != "" && file.CollectPipe && file.LimitBytes > 0 {
				collectors[file.Collector] = true
			}
		}
		ids := make(map[string]FileID, len(value.FileIDs))
		for name, id := range value.FileIDs {
			if _, ok := requested[name]; !ok || !id.valid() || inputIDs[id] || outputIDs[id] {
				return nil, &Error{Kind: ProtocolError}
			}
			ids[name] = id
			outputIDs[id] = true
		}
		if *value.Status == Accepted {
			for name, output := range requested {
				if _, found := ids[name]; !found && !output.Optional {
					return nil, &Error{Kind: ProtocolError}
				}
			}
		}
		fileErrorTypes := make([]FileErrorType, 0, len(value.FileError))
		sizeOnly, collectorOnly := len(value.FileError) > 0, len(value.FileError) > 0
		for _, failure := range value.FileError {
			if !failure.Type.valid() {
				return nil, &Error{Kind: ProtocolError}
			}
			fileErrorTypes = append(fileErrorTypes, failure.Type)
			_, outputRequested := requested[failure.Name]
			switch failure.Type {
			case CollectSizeExceeded:
				sizeOnly = sizeOnly && outputRequested && collectors[failure.Name]
				collectorOnly = collectorOnly && outputRequested && collectors[failure.Name] && failure.Message == pinnedCollectorOutputLimitError
			case CopyOutSizeExceeded:
				sizeOnly = sizeOnly && outputRequested && req.Commands[i].CopyOutMaxBytes > 0
				collectorOnly = false
			default:
				sizeOnly, collectorOnly = false, false
			}
		}
		totalFiles += len(ids)
		if totalFiles > limits.Files {
			return nil, &Error{Kind: BoundsError}
		}
		results[i] = Result{Status: *value.Status, ExitStatus: *value.ExitStatus, CPUTimeNS: *value.Time, WallTimeNS: *value.RunTime, MemoryBytes: *value.Memory, ProcessPeak: value.ProcPeak, CachedFiles: ids, HasError: value.Error != "", FileErrorCount: len(value.FileError), FileErrorTypes: fileErrorTypes, RequestedOutputSizeExceeded: sizeOnly, CollectorOutputLimitError: collectorOnly && value.Error == pinnedCollectorOutputLimitError}
	}
	return results, nil
}

// Exact go-sandbox v0.14.0/99ea73b runner.StatusOutputLimitExceeded.Error().
// The pinned go-judge collector returns this typed error for finite overflow.
// This equality creates a bounded structural fact; raw diagnostics are dropped.
const pinnedCollectorOutputLimitError = "Output Limit Exceeded"
