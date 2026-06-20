package gocq

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LagrangeDev/LagrangeGo/client/auth"
	"github.com/LagrangeDev/LagrangeGo/client/sign"
	"github.com/LagrangeDev/LagrangeGo/utils/io"
	log "github.com/sirupsen/logrus"

	"github.com/Mrs4s/go-cqhttp/internal/base"
	nativesign "github.com/Mrs4s/go-cqhttp/internal/sign/native"
	"github.com/Mrs4s/go-cqhttp/modules/config"
)

const serverLatencyDown = math.MaxUint32

const builtinSignServer = "builtin"

// ErrAllSignDown 所有签名服务器都不可用
var ErrAllSignDown = errors.New("all sign down")

type (
	signer struct {
		lock         sync.RWMutex
		instances    []*remote
		app          *auth.AppInfo
		extraHeaders http.Header
		doneChan     chan struct{}
	}

	remote struct {
		server  string
		token   string
		native  *nativesign.Signer
		latency atomic.Uint32
	}
)

func newSigner() *signer {
	return &signer{
		extraHeaders: http.Header{},
		doneChan:     make(chan struct{}),
	}
}

func (c *signer) init() {}

// Release 释放资源
func (c *signer) Release() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, instance := range c.instances {
		if instance.native != nil {
			instance.native.Close()
		}
	}
	close(c.doneChan)
}

// Sign 对数据包签名
func (c *signer) Sign(cmd string, seq uint32, data []byte, uin uint32, guid, qua string) (*sign.Response, error) {
	if !sign.ContainSignPKG(cmd) {
		return nil, nil
	}
	sortFlag := false
	defer func() {
		if sortFlag {
			c.sortByLatency()
		}
	}()
	// 防止死锁
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, instance := range c.instances {
		resp, err := instance.sign(cmd, seq, data, uin, guid, qua, c.extraHeaders)
		if err == nil {
			return resp, nil
		}
		sortFlag = true
		instance.latency.Store(serverLatencyDown)
		log.Errorf("签名时出现错误：%v", err)
	}
	return nil, ErrAllSignDown
}

func (c *signer) sortByLatency() {
	c.lock.Lock()
	defer c.lock.Unlock()
	sort.Slice(c.instances, func(i, j int) bool {
		return c.instances[i].latency.Load() < c.instances[j].latency.Load()
	})
}

// AddRequestHeader 添加请求头
func (c *signer) AddRequestHeader(header map[string]string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, v := range header {
		c.extraHeaders.Add(k, v)
	}
}

// AddSignServer 添加签名服务器
func (c *signer) AddSignServer(signServers ...config.SignServer) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, s := range signServers {
		rawURL := strings.TrimSpace(s.URL)
		if rawURL == "" || rawURL == "-" {
			continue
		}
		if dir, ok := parseBuiltinSignServer(rawURL); ok {
			instance, err := newBuiltinRemote(dir, s.Offset)
			if err != nil {
				log.Errorf("初始化内置签名失败：%v", err)
				continue
			}
			log.Infof("已启用内置签名：%s", instance.server)
			c.instances = append(c.instances, instance)
			continue
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		c.instances = append(c.instances, &remote{server: u.String(), token: s.Token})
	}
}

// GetSignServer 获取签名服务器
func (c *signer) GetSignServer() []string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return io.Map(c.instances, func(sign *remote) string {
		return sign.server
	})
}

// SetAppInfo 设置版本信息
func (c *signer) SetAppInfo(app *auth.AppInfo) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.app = app
	c.extraHeaders.Set("User-Agent", fmt.Sprintf("qq/%s (%s_%s) go-cqhttp/%s",
		app.CurrentVersion, runtime.GOOS, runtime.GOARCH, base.Version))
}

func parseBuiltinSignServer(rawURL string) (string, bool) {
	rawURL = strings.TrimSpace(rawURL)
	if strings.EqualFold(rawURL, builtinSignServer) || strings.EqualFold(rawURL, builtinSignServer+"://") {
		return "", true
	}
	if strings.HasPrefix(strings.ToLower(rawURL), builtinSignServer+":") {
		return strings.TrimSpace(rawURL[len(builtinSignServer)+1:]), true
	}
	return "", false
}

func newBuiltinRemote(dir, configuredOffset string) (*remote, error) {
	if envDir := strings.TrimSpace(os.Getenv("SIGN_WRAPPER_DIR")); envDir != "" {
		dir = envDir
	}
	offset, err := builtinSignOffset(configuredOffset)
	if err != nil {
		return nil, err
	}
	native, err := nativesign.New(nativesign.Config{
		Directory: dir,
		Offset:    offset,
	})
	if err != nil {
		return nil, err
	}
	server := builtinSignServer
	if dir != "" {
		server += ":" + dir
	}
	return &remote{server: server, native: native}, nil
}

func builtinSignOffset(configuredOffset string) (uintptr, error) {
	rawOffset := strings.TrimSpace(os.Getenv("SIGN_OFFSET"))
	if rawOffset == "" {
		rawOffset = strings.TrimSpace(configuredOffset)
	}
	if rawOffset == "" {
		return nativesign.DefaultOffset, nil
	}
	rawOffset = strings.TrimPrefix(strings.TrimPrefix(rawOffset, "0x"), "0X")
	offset, err := strconv.ParseUint(rawOffset, 16, 0)
	if err != nil {
		return 0, fmt.Errorf("解析 SIGN_OFFSET 失败: %w", err)
	}
	return uintptr(offset), nil
}

// func (c *signer) check() {
//	log.Infoln("开始签名服务器质量测试")
//	availableQuantity := 0
//	wg := sync.WaitGroup{}
//	c.lock.RLock()
//	for _, instance := range c.instances {
//		wg.Add(1)
//		go func(i *remote) {
//			defer wg.Done()
//			i.test()
//		}(instance)
//	}
//	wg.Wait()
//	for _, instance := range c.instances {
//		if instance.latency.Load() < serverLatencyDown {
//			availableQuantity++
//		}
//	}
//	c.lock.RUnlock()
//	c.sortByLatency()
//	log.Infof("签名服务器质量测试完成，可用服务器数量: %d", availableQuantity)
//}

func (i *remote) sign(cmd string, seq uint32, buf []byte, uin uint32, guid, qua string, header http.Header) (signResp *sign.Response, err error) {
	if !sign.ContainSignPKG(cmd) {
		return nil, nil
	}
	if i.native != nil {
		return i.signNative(cmd, seq, buf)
	}
	signReq := sign.Request{
		Command: cmd,
		Seq:     int(seq),
		Body:    buf,
		Uin:     uin,
		GUID:    guid,
		Qua:     qua,
	}
	u, err := url.Parse(i.server)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(&signReq)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if i.token != "" {
		req.Header.Set("Authorization", "Bearer "+i.token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&signResp)
	if err != nil {
		return nil, err
	}
	if signResp.Code != 0 {
		return nil, errors.New(signResp.Message)
	}

	return signResp, nil
}

func (i *remote) signNative(cmd string, seq uint32, buf []byte) (*sign.Response, error) {
	result, err := i.native.Sign(cmd, buf, int(seq))
	if err != nil {
		return nil, err
	}
	resp := &sign.Response{
		Code:    0,
		Message: "success",
	}
	resp.Value.SecSign = sign.HexData(result.Sign)
	resp.Value.SecToken = sign.HexData(result.Token)
	resp.Value.SecExtra = sign.HexData(result.Extra)
	return resp, nil
}

// func (i *remote) test() {
//	startTime := time.Now().UnixMilli()
//	resp, err := i.sign("wtlogin.login", 1, []byte{11, 45, 14}, 0, "", "", nil)
//	if err != nil || len(resp.Value.SecSign) == 0 {
//		log.Warnf("测试签名服务器：%s时出现错误: %v", i.server, err)
//		i.latency.Store(serverLatencyDown)
//		return
//	}
//	// 有长连接的情况，取两次平均值
//	resp, err = i.sign("wtlogin.login", 1, []byte{11, 45, 14}, 0, "", "", nil)
//	if err != nil || len(resp.Value.SecSign) == 0 {
//		log.Warnf("测试签名服务器：%s时出现错误: %v", i.server, err)
//		i.latency.Store(serverLatencyDown)
//		return
//	}
//	latency := (time.Now().UnixMilli() - startTime) / 2
//	i.latency.Store(uint32(latency))
//	log.Debugf("签名服务器：%s，延迟：%dms", i.server, latency)
//}
