// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// DetectBudget picks a conservative memory budget when none is configured
// (design §15: conservative factor, manual override always available):
// 90% of the first GPU's VRAM when nvidia-smi answers, else 50% of system
// RAM (CPU inference is RAM-bound).
func DetectBudget() (int64, string) {
	if vram, err := nvidiaVRAM(); err == nil && vram > 0 {
		return vram * 9 / 10, "gpu"
	}
	if ram, err := systemRAM(); err == nil && ram > 0 {
		return ram / 2, "ram"
	}
	return 8 << 30, "fallback" // pessimistic default: 8 GiB
}

// nvidiaVRAM returns the first GPU's total memory in bytes.
func nvidiaVRAM() (int64, error) {
	bin, err := exec.LookPath("nvidia-smi")
	if err != nil {
		return 0, err
	}
	out, err := exec.Command(bin, "--query-gpu=memory.total", "--format=csv,noheader,nounits").Output() // #nosec G204 -- fixed args, binary from PATH lookup
	if err != nil {
		return 0, err
	}
	line, _, _ := bytes.Cut(out, []byte("\n"))
	mib, err := strconv.ParseInt(strings.TrimSpace(string(line)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing nvidia-smi output %q: %w", line, err)
	}
	return mib << 20, nil
}

// systemRAM reads MemTotal from /proc/meminfo (Linux; other platforms fall
// back to the pessimistic default).
func systemRAM() (int64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(v, "kB")), 10, 64)
			if err != nil {
				return 0, err
			}
			return kb << 10, nil
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemTotal not found")
}

// ParseBudget parses human budget strings: plain bytes, or KiB/MiB/GiB/TiB
// suffixes (also accepts K/M/G/T shorthand).
func ParseBudget(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty budget")
	}
	mult := int64(1)
	upper := strings.ToUpper(s)
	for suffix, m := range map[string]int64{
		"KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40,
		"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40,
	} {
		if strings.HasSuffix(upper, suffix) {
			mult = m
			s = s[:len(s)-len(suffix)]
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid budget %q", s)
	}
	return int64(n * float64(mult)), nil
}
