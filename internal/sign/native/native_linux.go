//go:build linux && cgo

package native

/*
#cgo linux LDFLAGS: -Wl,--export-dynamic
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long long (*sign_func)(const char*, const unsigned char*, int, int, unsigned char*);

__attribute__((visibility("default"))) void qq_magic_napi_register(void* arg) {
	(void)arg;
}

static uintptr_t native_module_base;
static void* native_module_handle;
static sign_func native_sign;
static char native_last_error[2048];

static void native_set_error(const char* message, const char* detail) {
	if (detail == NULL) {
		detail = "unknown error";
	}
	snprintf(native_last_error, sizeof(native_last_error), "%s: %s", message, detail);
}

static int native_find_wrapper(struct dl_phdr_info* info, size_t size, void* data) {
	(void)size;
	const char* needle = (const char*)data;
	if (info->dlpi_name && strstr(info->dlpi_name, needle)) {
		native_module_base = info->dlpi_addr;
		return 1;
	}
	return 0;
}

static const char* native_error() {
	return native_last_error;
}

static void native_keep_symbols() {
	volatile void* ref = (void*)&qq_magic_napi_register;
	(void)ref;
}

static int native_load(char** libs, int lib_count, const char* module_path, uintptr_t offset) {
	native_last_error[0] = '\0';
	native_module_base = 0;
	native_sign = NULL;

	for (int i = 0; i < lib_count; i++) {
		void* handle = dlopen(libs[i], RTLD_LAZY | RTLD_GLOBAL);
		if (!handle) {
			native_set_error("preload failed", dlerror());
			return 1;
		}
	}

	native_module_handle = dlopen(module_path, RTLD_LAZY);
	if (!native_module_handle) {
		native_set_error("dlopen wrapper.node failed", dlerror());
		return 1;
	}

	dl_iterate_phdr(native_find_wrapper, "wrapper.node");
	if (native_module_base == 0) {
		native_set_error("wrapper.node base not found", module_path);
		dlclose(native_module_handle);
		native_module_handle = NULL;
		return 1;
	}

	native_sign = (sign_func)(native_module_base + offset);
	if ((uintptr_t)native_sign < 0x10000) {
		native_set_error("invalid sign function pointer", module_path);
		dlclose(native_module_handle);
		native_module_handle = NULL;
		native_sign = NULL;
		return 1;
	}

	return 0;
}

static void native_unload() {
	if (native_module_handle) {
		dlclose(native_module_handle);
		native_module_handle = NULL;
	}
	native_module_base = 0;
	native_sign = NULL;
}

static long long native_call(const char* cmd, const unsigned char* src, int src_len, int seq, unsigned char* out) {
	if (!native_sign) {
		native_set_error("sign function is not loaded", "");
		return -1;
	}
	return native_sign(cmd, src, src_len, seq, out);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"
)

const DefaultOffset uintptr = 0x5BD3EA1

type Config struct {
	Directory   string
	Offset      uintptr
	PreloadLibs []string
}

type Result struct {
	Token []byte
	Extra []byte
	Sign  []byte
}

type Signer struct {
	mu          sync.Mutex
	modulePath  string
	offset      uintptr
	preloadLibs []string
	loaded      bool
}

func New(config Config) (*Signer, error) {
	C.native_keep_symbols()

	offset := config.Offset
	if offset == 0 {
		offset = DefaultOffset
	}

	dir := strings.TrimSpace(config.Directory)
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	modulePath := filepath.Join(absDir, "wrapper.node")
	if _, err := os.Stat(modulePath); err != nil {
		return nil, fmt.Errorf("find wrapper.node: %w", err)
	}

	preloadLibs := append([]string{}, config.PreloadLibs...)
	if len(preloadLibs) == 0 {
		preloadLibs = []string{
			"libgnutls.so.30",
		}
	}

	return &Signer{
		modulePath:  modulePath,
		offset:      offset,
		preloadLibs: preloadLibs,
	}, nil
}

func (s *Signer) Sign(cmd string, src []byte, seq int) (*Result, error) {
	if strings.IndexByte(cmd, 0) >= 0 {
		return nil, errors.New("command contains NUL byte")
	}
	if len(src) > math.MaxInt32 {
		return nil, errors.New("body is too large")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.loadLocked(); err != nil {
		return nil, err
	}

	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	var srcPtr *C.uchar
	if len(src) > 0 {
		srcPtr = (*C.uchar)(unsafe.Pointer(&src[0]))
	}

	var out [0x300]byte
	ret := C.native_call(
		cCmd,
		srcPtr,
		C.int(len(src)),
		C.int(seq),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if ret < 0 {
		return nil, cError("native sign")
	}

	token := copyRegion(out[:], 0x000, 0x0FF)
	extra := copyRegion(out[:], 0x100, 0x1FF)
	sign := copyRegion(out[:], 0x200, 0x2FF)
	return &Result{Token: token, Extra: extra, Sign: sign}, nil
}

func (s *Signer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		C.native_unload()
		s.loaded = false
	}
}

func (s *Signer) loadLocked() error {
	if s.loaded {
		return nil
	}

	cModulePath := C.CString(s.modulePath)
	defer C.free(unsafe.Pointer(cModulePath))

	cLibs := make([]*C.char, len(s.preloadLibs))
	for i, lib := range s.preloadLibs {
		cLibs[i] = C.CString(lib)
		defer C.free(unsafe.Pointer(cLibs[i]))
	}

	var cLibsPtr **C.char
	if len(cLibs) > 0 {
		cLibsPtr = (**C.char)(unsafe.Pointer(&cLibs[0]))
	}

	if C.native_load(cLibsPtr, C.int(len(cLibs)), cModulePath, C.uintptr_t(s.offset)) != 0 {
		return cError("load wrapper.node")
	}
	s.loaded = true
	return nil
}

func cError(context string) error {
	msg := C.GoString(C.native_error())
	if msg == "" {
		msg = "unknown error"
	}
	return fmt.Errorf("%s: %s", context, msg)
}

func copyRegion(buf []byte, dataOffset, lenOffset int) []byte {
	n := int(buf[lenOffset])
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	copy(out, buf[dataOffset:dataOffset+n])
	return out
}
