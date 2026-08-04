//go:build !windows

package googleipmi

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2/transport/googleec"
	"github.com/u-root/u-root/pkg/ipmi"
	"github.com/u-root/u-root/pkg/ipmi/blobs"
)

const (
	blobOverhead       = 3 + 1 + 2 + 2 + 4 // OEN, subcommand, CRC, blob handle, offset
	maxBlobPayloadSize = 64
	maxChunkSize       = maxBlobPayloadSize - blobOverhead

	// The maximum size of a Titan EC command or response over ipmi
	maxTitanResponseSize = 1024
	// IPMI blob protocol commit times are not distributed linearly, so use an exponential backoff.
	// These values are tuned to catch the 90th percentile delay in 3 polls or less.
	initialPollPeriod        = 4 * time.Millisecond
	exponentialBackoffFactor = 1.5
)

var (
	titanPathCandidates = []string{"/dev/hoth/command_passthru"}
)

// dispatcher implements the commandDispatcher interface.
type dispatcher struct {
	ipmi     *ipmi.IPMI
	blobs    *blobs.BlobHandler
	blobPath string
}

// new initializes a new connection to the Titan over ipmi.
func new(opts options) (*dispatcher, error) {
	ipmi, err := ipmi.OpenPath(opts.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("could not open ipmi device %q: %w", opts.DevicePath, err)
	}
	blobs := blobs.NewBlobHandler(ipmi)
	blobPath, err := findBlobPath(blobs)
	if err != nil {
		return nil, fmt.Errorf("could not find blob path: %w", err)
	}
	return &dispatcher{
		ipmi:     ipmi,
		blobs:    blobs,
		blobPath: blobPath,
	}, nil
}

// DispatchCommand implements googleec.CommandDispatcher.
func (d *dispatcher) DispatchCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	session, err := d.blobs.BlobOpen(d.blobPath, blobs.BMC_BLOB_OPEN_FLAG_READ|blobs.BMC_BLOB_OPEN_FLAG_WRITE)
	if err != nil {
		return nil, fmt.Errorf("could not open blob %q: %w", d.blobPath, err)
	}
	defer d.blobs.BlobClose(session)

	if err := d.write(ctx, session, cmd); err != nil {
		return nil, err
	}

	return d.read(ctx, session)
}

// DispatchCommandNoResponse implements googleec.CommandDispatcher.
func (d *dispatcher) DispatchCommandNoResponse(ctx context.Context, cmd []byte) error {
	session, err := d.blobs.BlobOpen(d.blobPath, blobs.BMC_BLOB_OPEN_FLAG_READ|blobs.BMC_BLOB_OPEN_FLAG_WRITE)
	if err != nil {
		return fmt.Errorf("could not open blob %q: %w", d.blobPath, err)
	}
	defer d.blobs.BlobClose(session)

	return d.write(ctx, session, cmd)
}

// options contain the configuration settings for connecting to a Titan over ipmi.
type options struct {
	// The path to the IPMI device, e.g., /dev/ipmi0.
	DevicePath string
}

// write sends an EC command to the Titan.
func (d *dispatcher) write(ctx context.Context, sid blobs.SessionID, cmd []byte) error {
	// Send the complete formatted EC command in chunks.
	numChunks := (len(cmd) + maxChunkSize - 1) / maxChunkSize
	for chunk := 0; chunk < numChunks; chunk++ {
		chunkBegin := chunk * maxChunkSize
		chunkEnd := chunkBegin + maxChunkSize
		if chunkEnd > len(cmd) {
			chunkEnd = len(cmd)
		}
		chunkAddress := uint32(chunkBegin)
		if err := d.blobs.BlobWrite(sid, chunkAddress, cmd[chunkBegin:chunkEnd]); err != nil {
			return fmt.Errorf("sending chunk %d of %d: %w", chunk+1, numChunks, err)
		}
	}
	return d.commit(ctx, sid)
}

func (d *dispatcher) commit(ctx context.Context, sid blobs.SessionID) error {
	if err := d.blobs.BlobCommit(sid, nil); err != nil {
		return fmt.Errorf("committing blob: %w", err)
	}
	// We have to poll the blob until it reaches the COMMITTED state.
	stats, err := d.blobs.BlobSessionStat(sid)
	if err != nil {
		return fmt.Errorf("could not stat blob: %w", err)
	}
	committed := stats.State&blobs.BMC_BLOB_STATE_COMMITTED == blobs.BMC_BLOB_STATE_COMMITTED
	pollPeriod := initialPollPeriod
	for !committed {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for Titan to respond to EC command")
		case <-time.After(pollPeriod):
			stats, err = d.blobs.BlobSessionStat(sid)
			if err != nil {
				return fmt.Errorf("could not stat blob: %w", err)
			}
			if stats.State&blobs.BMC_BLOB_STATE_COMMIT_ERROR == blobs.BMC_BLOB_STATE_COMMIT_ERROR {
				return fmt.Errorf("failed to commit blob")
			}
			committed = stats.State&blobs.BMC_BLOB_STATE_COMMITTED == blobs.BMC_BLOB_STATE_COMMITTED
			pollPeriod = time.Duration(float64(pollPeriod) * exponentialBackoffFactor)
		}
	}
	return nil
}

// read reads an EC response from the Titan.
func (d *dispatcher) read(ctx context.Context, sid blobs.SessionID) ([]byte, error) {
	// Read the beginning of the response, which contains the EC response header.
	hdr, err := d.blobs.BlobRead(sid, 0, googleec.HostHeaderLen)
	if err != nil {
		return nil, err
	}

	// Parse the EC response header to check for errors and find the size of the rest of the response.
	dataLen, err := googleec.PeekResponse(hdr)
	if err != nil {
		return nil, err
	}
	if dataLen > maxTitanResponseSize {
		return nil, fmt.Errorf("got too-large EC response size of %d from Titan", dataLen)
	}

	data := make([]byte, 0, dataLen)
	dataEnd := uint32(googleec.HostHeaderLen + dataLen)
	// Read the rest of the response data (if any) in chunks.
	for chunkBegin := uint32(googleec.HostHeaderLen); chunkBegin < dataEnd; chunkBegin += maxChunkSize {
		chunkEnd := chunkBegin + maxChunkSize
		if chunkEnd > dataEnd {
			chunkEnd = dataEnd
		}
		chunkData, err := d.blobs.BlobRead(sid, chunkBegin, chunkEnd-chunkBegin)
		if err != nil {
			return nil, err
		}
		data = append(data, chunkData...)
	}
	return append(hdr, data...), nil
}

// findBlobPath searches the blob protocol for the expected Titan blob path.
func findBlobPath(bh *blobs.BlobHandler) (string, error) {
	for _, candidate := range titanPathCandidates {
		sess, err := bh.BlobOpen(candidate, blobs.BMC_BLOB_OPEN_FLAG_READ|blobs.BMC_BLOB_OPEN_FLAG_WRITE)
		if err != nil {
			continue
		}
		if err = bh.BlobClose(sess); err != nil {
			return "", fmt.Errorf("found %q, but could not close it: %w", candidate, err)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("could not find Titan blob protocol blob")
}

// Close closes the ipmi connection to the Titan.
func (d *dispatcher) Close() error {
	return d.ipmi.Close()
}
