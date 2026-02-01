package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"zmscan/backend/poc"
)

// Scanner 扫描器
type Scanner struct {
	httpClient  *http.Client
	manager     *poc.POCManager
	maxWorkers  int
	timeout     time.Duration
	resultChan  chan *poc.ScanResult
	progress    *Progress
	progressMu  sync.Mutex
}

// Progress 扫描进度
type Progress struct {
	Total      int
	Completed  int
	Vulnerable int
}

// ScanRequest 扫描请求
type ScanRequest struct {
	Targets   []string // 目标地址列表 (格式: host:port)
	POCID     string   // POC ID，空表示使用所有POC
	Category  string   // POC分类，空表示所有分类
	MaxWorkers int     // 最大并发数
	Timeout   int      // 超时时间(秒)
}

// ScannerOption 扫描器配置选项
type ScannerOption func(*Scanner)

// WithMaxWorkers 设置最大并发数
func WithMaxWorkers(n int) ScannerOption {
	return func(s *Scanner) {
		s.maxWorkers = n
	}
}

// WithTimeout 设置超时时间
func WithTimeout(t time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.timeout = t
	}
}

// NewScanner 创建扫描器
func NewScanner(manager *poc.POCManager, opts ...ScannerOption) *Scanner {
	s := &Scanner{
		manager:    manager,
		maxWorkers: 50,
		timeout:    10 * time.Second,
		resultChan: make(chan *poc.ScanResult, 100),
		progress:   &Progress{},
	}

	// 配置HTTP客户端
	s.httpClient = &http.Client{
		Timeout: s.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	// 应用选项
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Scan 执行扫描
func (s *Scanner) Scan(ctx context.Context, req *ScanRequest) (<-chan *poc.ScanResult, *Progress) {
	// 重置进度
	s.progressMu.Lock()
	s.progress = &Progress{Total: 0}
	s.progressMu.Unlock()

	// 获取要使用的POC列表
	pocs := s.getPOCsForScan(req)

	// 计算总任务数
	totalTasks := len(req.Targets) * len(pocs)
	s.progressMu.Lock()
	s.progress.Total = totalTasks
	s.progressMu.Unlock()

	// 创建工作池
	go s.runWorkers(ctx, req.Targets, pocs, req)

	return s.resultChan, s.progress
}

// getPOCsForScan 获取本次扫描要使用的POC
func (s *Scanner) getPOCsForScan(req *ScanRequest) []*poc.POC {
	var pocs []*poc.POC

	// 指定POC ID
	if req.POCID != "" {
		if p, ok := s.manager.GetPOC(req.POCID); ok {
			pocs = append(pocs, p)
		}
		return pocs
	}

	// 指定分类
	if req.Category != "" {
		return s.manager.GetPOCsByCategory(req.Category)
	}

	// 使用所有POC
	return s.manager.GetPOCs()
}

// runWorkers 运行工作池
func (s *Scanner) runWorkers(ctx context.Context, targets []string, pocs []*poc.POC, req *ScanRequest) {
	defer close(s.resultChan)

	var wg sync.WaitGroup

	// 任务通道
	taskChan := make(chan *scanTask, s.maxWorkers*2)

	// 启动工作协程
	maxWorkers := s.maxWorkers
	if req.MaxWorkers > 0 {
		maxWorkers = req.MaxWorkers
	}

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, taskChan)
	}

	// 分发任务
	for _, target := range targets {
		for _, p := range pocs {
			select {
			case taskChan <- &scanTask{
				target: target,
				poc:    p,
			}:
			case <-ctx.Done():
				break
			}
		}
	}
	close(taskChan)

	// 等待所有工作完成
	wg.Wait()
}

// scanTask 扫描任务
type scanTask struct {
	target string
	poc    *poc.POC
}

// worker 工作协程
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, taskChan <-chan *scanTask) {
	defer wg.Done()

	for {
		select {
		case task, ok := <-taskChan:
			if !ok {
				return
			}

			result := s.scanTarget(task.target, task.poc)

			// 更新进度
			s.progressMu.Lock()
			s.progress.Completed++
			if result.Vulnerable {
				s.progress.Vulnerable++
			}
			s.progressMu.Unlock()

			// 发送结果
			select {
			case s.resultChan <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// scanTarget 扫描单个目标
func (s *Scanner) scanTarget(target string, p *poc.POC) *poc.ScanResult {
	result := &poc.ScanResult{
		POCID:     p.ID,
		POCName:   p.Name,
		Target:    target,
		Severity:  p.Severity,
		Vulnerable: false,
		Message:   "扫描完成",
	}

	// 根据协议类型选择扫描方式
	switch strings.ToLower(p.Target.Protocol) {
	case "http", "https":
		return s.scanHTTP(target, p)
	case "tcp":
		return s.scanTCP(target, p)
	case "udp":
		return s.scanUDP(target, p)
	default:
		result.Message = fmt.Sprintf("不支持的协议: %s", p.Target.Protocol)
		return result
	}
}

// scanHTTP HTTP/HTTPS扫描
func (s *Scanner) scanHTTP(target string, p *poc.POC) *poc.ScanResult {
	result := &poc.ScanResult{
		POCID:     p.ID,
		POCName:   p.Name,
		Target:    target,
		Severity:  p.Severity,
		Vulnerable: false,
		Message:   "扫描完成",
	}

	// 构建URL
	scheme := "http"
	if strings.Contains(target, ":443") || strings.ToLower(p.Target.Protocol) == "https" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, target, p.Target.Path)

	// 创建请求
	var bodyReader io.Reader
	if p.Target.Body != "" {
		bodyReader = strings.NewReader(p.Target.Body)
	}

	req, err := http.NewRequest(p.Target.Method, url, bodyReader)
	if err != nil {
		result.Message = fmt.Sprintf("创建请求失败: %v", err)
		return result
	}

	// 设置请求头
	for k, v := range p.Target.Headers {
		req.Header.Set(k, v)
	}

	// 发送请求
	startTime := time.Now()
	resp, err := s.httpClient.Do(req)
	responseTime := time.Since(startTime)

	if err != nil {
		result.Message = fmt.Sprintf("请求失败: %v", err)
		return result
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Message = fmt.Sprintf("读取响应失败: %v", err)
		return result
	}

	// 验证条件
	vulnerable := true
	var messages []string

	for _, cond := range p.Conditions {
		match, msg := s.checkCondition(resp, respBody, responseTime, cond)
		if !match {
			vulnerable = false
			if msg != "" {
				messages = append(messages, msg)
			}
		}
	}

	result.Vulnerable = vulnerable
	if vulnerable {
		result.Message = "存在漏洞"
		result.Details = string(respBody)
	} else if len(messages) > 0 {
		result.Message = strings.Join(messages, "; ")
	}

	return result
}

// checkCondition 检查条件
func (s *Scanner) checkCondition(resp *http.Response, body []byte, responseTime time.Duration, cond poc.Condition) (bool, string) {
	switch cond.Type {
	case "status":
		return s.checkStatus(resp.StatusCode, cond)
	case "body":
		return s.checkBody(body, cond)
	case "header":
		return s.checkHeader(resp, cond)
	case "response_time":
		return s.checkResponseTime(responseTime, cond)
	default:
		return false, fmt.Sprintf("未知的条件类型: %s", cond.Type)
	}
}

// checkStatus 检查响应码
func (s *Scanner) checkStatus(statusCode int, cond poc.Condition) (bool, string) {
	switch cond.Operator {
	case "equals":
		return fmt.Sprintf("%v", cond.Value) == fmt.Sprintf("%d", statusCode), ""
	case "not_equals":
		return fmt.Sprintf("%v", cond.Value) != fmt.Sprintf("%d", statusCode), ""
	case "greater":
		expected, _ := strconv.Atoi(fmt.Sprintf("%v", cond.Value))
		return statusCode > expected, ""
	case "less":
		expected, _ := strconv.Atoi(fmt.Sprintf("%v", cond.Value))
		return statusCode < expected, ""
	case "range":
		parts := strings.Split(fmt.Sprintf("%v", cond.Value), ",")
		if len(parts) == 2 {
			min, _ := strconv.Atoi(parts[0])
			max, _ := strconv.Atoi(parts[1])
			return statusCode >= min && statusCode <= max, ""
		}
		return false, "range格式错误"
	default:
		return false, fmt.Sprintf("未知的操作符: %s", cond.Operator)
	}
}

// checkBody 检查响应体
func (s *Scanner) checkBody(body []byte, cond poc.Condition) (bool, string) {
	bodyStr := string(body)
	value := fmt.Sprintf("%v", cond.Value)

	switch cond.Operator {
	case "contains":
		return strings.Contains(bodyStr, value), ""
	case "not_contains":
		return !strings.Contains(bodyStr, value), ""
	case "equals":
		return bodyStr == value, ""
	case "matches":
		matched, err := regexp.MatchString(value, bodyStr)
		return matched, err.Error()
	case "not_matches":
		matched, err := regexp.MatchString(value, bodyStr)
		return !matched, err.Error()
	case "json_path":
		// 简化处理，实际需要JSON Path解析库
		return strings.Contains(bodyStr, value), ""
	default:
		return false, fmt.Sprintf("未知的操作符: %s", cond.Operator)
	}
}

// checkHeader 检查响应头
func (s *Scanner) checkHeader(resp *http.Response, cond poc.Condition) (bool, string) {
	if cond.Name == "" {
		return false, "未指定header名称"
	}

	value := resp.Header.Get(cond.Name)
	expected := fmt.Sprintf("%v", cond.Value)

	switch cond.Operator {
	case "contains":
		return strings.Contains(value, expected), ""
	case "not_contains":
		return !strings.Contains(value, expected), ""
	case "equals":
		return value == expected, ""
	case "matches":
		matched, err := regexp.MatchString(expected, value)
		return matched, err.Error()
	default:
		return false, fmt.Sprintf("未知的操作符: %s", cond.Operator)
	}
}

// checkResponseTime 检查响应时间
func (s *Scanner) checkResponseTime(responseTime time.Duration, cond poc.Condition) (bool, string) {
	expected, _ := strconv.Atoi(fmt.Sprintf("%v", cond.Value))
	expectedTime := time.Duration(expected) * time.Millisecond

	switch cond.Operator {
	case "greater":
		return responseTime > expectedTime, ""
	case "less":
		return responseTime < expectedTime, ""
	case "equals":
		return responseTime == expectedTime, ""
	default:
		return false, fmt.Sprintf("未知的操作符: %s", cond.Operator)
	}
}

// scanTCP TCP端口扫描
func (s *Scanner) scanTCP(target string, p *poc.POC) *poc.ScanResult {
	result := &poc.ScanResult{
		POCID:     p.ID,
		POCName:   p.Name,
		Target:    target,
		Severity:  p.Severity,
		Vulnerable: false,
		Message:   "TCP扫描暂未实现",
	}

	// 解析目标地址
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		result.Message = fmt.Sprintf("解析目标失败: %v", err)
		return result
	}

	// 连接目标
	timeout := time.Duration(p.Target.Timeout) * time.Second
	if timeout == 0 {
		timeout = s.timeout
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		result.Message = "连接失败"
		return result
	}
	defer conn.Close()

	// 发送数据
	if p.Target.Body != "" {
		_, err = conn.Write([]byte(p.Target.Body))
		if err != nil {
			result.Message = fmt.Sprintf("发送数据失败: %v", err)
			return result
		}

		// 读取响应
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			result.Message = fmt.Sprintf("读取响应失败: %v", err)
			return result
		}

		// 检查条件
		respBody := string(buf[:n])
		for _, cond := range p.Conditions {
			if cond.Type == "body" {
				match, _ := s.checkBody([]byte(respBody), cond)
				if match {
					result.Vulnerable = true
					result.Message = "存在漏洞"
					result.Details = respBody
				}
			}
		}
	} else {
		// 端口开放即认为可能存在漏洞
		result.Vulnerable = true
		result.Message = "端口开放"
	}

	return result
}

// scanUDP UDP端口扫描
func (s *Scanner) scanUDP(target string, p *poc.POC) *poc.ScanResult {
	result := &poc.ScanResult{
		POCID:     p.ID,
		POCName:   p.Name,
		Target:    target,
		Severity:  p.Severity,
		Vulnerable: false,
		Message:   "UDP扫描暂未实现",
	}

	return result
}

// GetProgress 获取当前进度
func (s *Scanner) GetProgress() *Progress {
	s.progressMu.Lock()
	defer s.progressMu.Unlock()

	return &Progress{
		Total:      s.progress.Total,
		Completed:  s.progress.Completed,
		Vulnerable: s.progress.Vulnerable,
	}
}
